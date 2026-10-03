# -*- coding: utf-8 -*-
"""自動更新邏輯 — 純網路／檔案處理，無 Qt 依賴 (方便單獨測試)。

流程：
1. check_update()     → 查 GitHub Release API，比對版本，回傳更新資訊或 None。
2. stage_update()     → 下載 zip + SHA256 清單 → 校驗 → 解壓到 <dist>.new。
3. apply_and_restart() → 寫入背景替換腳本並啟動，主程式隨後自行關閉。

下載採多線程分段 (HTTP Range)：GitHub release 資產在部分網路環境單線只有
數十 KB/s，切成多段並行可大幅縮短時間。同時回報進度、偵測停滯並重試；
伺服器不支援 Range 時自動退回單線串流。GitHub 的資產是簽名 URL，探測時
取得轉址後的最終 URL 供所有分段共用，省去每段重走一次 302。

安全要求：下載的更新檔必須通過 SHA-256 校驗才會解壓、替換，否則中止。
"""

import collections
import glob
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from urllib.parse import quote

import requests

from version import UPDATE_API_URL

_TIMEOUT_CHECK = 15       # 檢查更新 (API) 逾時秒數
_TIMEOUT_CONNECT = 15     # 建立連線逾時秒數
_TIMEOUT_READ = 20        # 單次讀取逾時秒數 (超過此時間沒收到資料視為斷線)。
                          # Windows 無法從其他執行緒取消阻塞中的 recv，卡住的
                          # 讀取只能靠這個逾時自行返回，因此不宜設得太大。
_TIMEOUT_DOWNLOAD = 180   # SHA256 清單等下載的逾時秒數

# --- 多線程分段下載參數 ---
DOWNLOAD_THREADS = 8                  # 預設並行連線數 (= worker 執行緒上限)
# 單段大小下限。這是實測調出來的，不是拍的：
# GitHub release CDN 每次 Range 請求的「發出 -> 回應標頭」要 1.27~1.73 秒，
# 而 1 MB 資料在 300 Mbps 上只帶 27 毫秒 —— 1 MB 分段有 98% 的時間在等這個
# 固定延遲。實測同一個 34 MB 資產 (2026-10-03)：
#     32 段 x 1.0MB -> 直連 65.2 Mbps，代理直接 Read timed out
#      8 段 x 4.1MB -> 直連 93.4 Mbps
#      4 段 x 8.2MB -> 直連 107.7 Mbps
#      1 段 x 32.7MB -> 直連 107.2 Mbps
# 段數越少越快，故下限設 8 MB、上限 8 段。
MIN_BLOCK_SIZE = 8 * 1024 * 1024      # 單段大小下限 (見上)
MAX_BLOCKS = 8                        # 分段數上限 (= 最大並行連線數)
MIN_MULTIPART_SIZE = 4 * 1024 * 1024  # 小於此大小不值得分段，直接單線
CHUNK_SIZE = 256 * 1024               # 每次讀取的位元組數
STALL_WINDOW = 30                     # 停滯偵測視窗 (秒)
STALL_MIN_BYTES = 128 * 1024          # 視窗內至少需收到的位元組，否則視為停滯
MAX_BLOCK_RETRIES = 4                 # 單一分段最大重試次數
NO_PROGRESS_TIMEOUT = 45              # 整體位元組數連續無成長達此秒數 → 放棄本次下載
STOP_GRACE = 25                       # stop 設起後仍存活的下載執行緒，最多再等此秒數
                                      # (需大於 _TIMEOUT_READ，讓阻塞讀取自行逾時退出)
# GitHub release CDN 常以「突發」方式送資料：短時間內灌一批、然後停頓。
# 用 0.5 秒瞬時速度估算時，幾乎每個停頓窗都會顯示 0 B/s（實測 32.7 MB 的
# 下載出現 183/243 個 0 速度樣本），看起來像不斷歸零。改用數秒滑動視窗
# 取平均，才反映真實吞吐。
SPEED_WINDOW = 3.0                    # 速度平滑視窗 (秒)
USER_AGENT = "NetRedirector-Updater"

# --- 代理 / 智能分流 ---
PROXY_CONFIG_FILENAME = "config.json" # 代理清單來源 (與主程式共用)
# 不指定代理那條候選路徑的顯示名稱。刻意不叫「直連」：當引擎正在全局轉發
# (規則 target='*'、action=PROXY) 時，這條路徑其實也被 WinDivert 攔下來
# 轉到同一個代理，根本沒走實體線。叫「直連」會讓使用者以為下載走的是
# PPPoE 實體線（2026-10-03 實測：兩條路的出口 IP 完全相同，
# 49.215.44.84，證明它們是同一條 5G 行動網路）。
DIRECT_LABEL = "系統路由（未指定代理）"
PROXY_PROBE_TIMEOUT = 6               # 等第一個位元組的逾時 (秒)
PROXY_PROBE_SECONDS = 1.5             # 首個位元組之後，最多量這麼久的吞吐
PROXY_PROBE_MAX_BYTES = 8 * 1024 * 1024   # 量測視窗的位元組上限
PROXY_PROBE_MIN_SECONDS = 0.3         # 視窗短於此值視為樣本不足，不予採用
PROXY_PROBE_TOTAL_TIMEOUT = 8         # 全部路徑量測的總逾時 (秒)

# --- 自適應連線數 (見 _adaptive_threads) ---
# 總開關。預設關閉：關閉時 threads 完全由呼叫端決定，行為與舊版一模一樣。
# 也可以在 config.json 頂層寫 "adaptive_concurrency": true 單獨打開。
ADAPTIVE_CONCURRENCY = False
ADAPTIVE_CONCURRENCY_KEY = "adaptive_concurrency"
ADAPTIVE_PROBE_THREADS = 4           # 試探時開幾條連線
ADAPTIVE_PROBE_SECONDS = 1.2         # 試探的共同視窗長度 (秒)
ADAPTIVE_GAIN = 1.35                 # 聚合吞吐至少要贏基準這麼多倍才值得多開
ADAPTIVE_LATENCY_TOLERANCE = 1.25    # 連線延遲最多可漲這麼多倍 (Vegas 式煞車)
# 試探本身要付 (TTFB + 視窗) ≈ 2.5 秒；多開連線能省下的時間是 est*(1-1/gain)，
# 要打平得 est > 2.5 * gain/(gain-1) ≈ 9.6 秒 (gain=1.35)。估計下載時間不到這個
# 門檻就不試探 —— 試探成本比可能省下的還多。實務上這代表：快線（30 MB 資產
# 只要 3~4 秒）不會啟動，慢線（數十 KB/s 起跳）才會 —— 而慢線正是這個
# updater 存在的理由。
ADAPTIVE_MIN_EST_SECONDS = 10.0
ADAPTIVE_MIN_BYTES = 16 * 1024 * 1024   # 檔案太小也不值得分段試探


class UpdateCancelled(Exception):
    """使用者取消了更新下載。"""


def parse_semver(tag):
    """把 git tag (可能帶 v 前綴) 轉成純版本字串。"""
    t = (tag or "").strip()
    if t.lower().startswith("v"):
        t = t[1:]
    return t


def _version_tuple(v):
    """把 "1.10.0" 轉成可比較的整數 tuple，避免字串比對 "1.10.0" < "1.9.0" 的錯誤。"""
    parts = []
    for p in str(v).split("."):
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _is_newer(latest, current):
    return _version_tuple(latest) > _version_tuple(current)


def get_latest_release(timeout=_TIMEOUT_CHECK):
    """呼叫 GitHub Releases API 取得最新 release JSON。"""
    r = requests.get(
        UPDATE_API_URL,
        timeout=timeout,
        headers={"Accept": "application/vnd.github+json"},
    )
    r.raise_for_status()
    return r.json()


def check_update(current_version, timeout=_TIMEOUT_CHECK):
    """比對最新 release 與目前版本。

    回傳 None 表示已是最新；有新版本時回傳 dict:
        {"version", "asset_name", "url", "checksum_url", "notes", "size"}
    網路錯誤 / 資產缺失時拋出例外，由呼叫端處理。
    """
    release = get_latest_release(timeout)
    latest = parse_semver(release.get("tag_name", ""))
    if not latest or not _is_newer(latest, current_version):
        return None

    assets = release.get("assets", [])
    zip_asset = next(
        (a for a in assets if a.get("name", "").lower().endswith(".zip")), None)
    checksum_asset = next(
        (a for a in assets
         if a.get("name", "").lower() in ("sha256sums.txt", "sha256.txt", "checksums.txt")),
        None)

    if not zip_asset or not checksum_asset:
        raise RuntimeError("release 缺少 zip 或 SHA256 資產，無法安全更新")

    return {
        "version": latest,
        "asset_name": zip_asset["name"],
        "url": zip_asset["browser_download_url"],
        "checksum_url": checksum_asset["browser_download_url"],
        "notes": release.get("body") or "",
        "size": zip_asset.get("size", 0),
    }


def verify_sha256(path, expected_hex):
    """計算檔案 SHA-256 並與期望值 (十六進位字串) 比對。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower() == str(expected_hex).strip().lower()


def _parse_expected_sha256(checksum_text, asset_name):
    """從 SHA256SUMS 內文找出指定資產的雜湊值 (格式: "<hash>  <name>")。"""
    for line in checksum_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and asset_name in line:
            return parts[0].strip()
    return None


def is_frozen():
    """是否執行於打包後的可執行檔。

    - PyInstaller / cx_Freeze 會設 ``sys.frozen``
    - PyInstaller onefile 會設 ``sys._MEIPASS``
    - Nuitka 不會設 ``sys.frozen``，而是在每個編譯模組的 globals 注入
      ``__compiled__ = True``（此函式的 globals 即為 updater 模組字典）
    """
    if getattr(sys, "frozen", False):
        return True
    if hasattr(sys, "_MEIPASS"):
        return True
    if globals().get("__compiled__", False):
        return True
    return False


def _frozen_exe_path():
    """取得打包後真正的執行檔路徑。

    Nuitka standalone 會把 ``sys.executable`` 指到內建的 ``python.exe``
    (而非真正的 IntegratedApp.exe)，導致 exe 名稱被誤判為 "python"、
    替換腳本等錯程序。故以 ``sys.argv[0]`` 為準，失敗時回退 ``sys.executable``。
    """
    argv0 = sys.argv[0] if sys.argv else ""
    p = os.path.abspath(argv0) if argv0 else ""
    if p and p.lower().endswith(".exe"):
        return p
    return os.path.abspath(sys.executable)


def current_dist_dir():
    """目前執行檔所在資料夾 (打包後即 .dist 目錄)。"""
    if is_frozen():
        return os.path.dirname(_frozen_exe_path())
    return os.path.dirname(os.path.abspath(__file__))


# ------------------------------------------------------------------ #
# 路徑選擇 (直連 vs 設定的代理) — 智能分流 + 防呆
# ------------------------------------------------------------------ #
def _config_search_paths():
    """回傳可能存放 config.json 的路徑 (依序、去重)。

    主程式以相對路徑開啟 "config.json" (cwd)，打包後 cwd 未必等於執行檔
    目錄，故三個位置都找：執行檔目錄、目前工作目錄、原始碼目錄。
    """
    candidates = []
    try:
        candidates.append(os.path.join(current_dist_dir(), PROXY_CONFIG_FILENAME))
    except Exception:  # noqa: BLE001
        pass
    candidates.append(os.path.abspath(PROXY_CONFIG_FILENAME))
    candidates.append(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), PROXY_CONFIG_FILENAME))
    seen = []
    for p in candidates:
        if p and p not in seen:
            seen.append(p)
    return seen


def _proxy_map(proxy_url):
    """把單一代理 URL 轉成 requests 的 proxies dict；無代理回 None。"""
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


def _proxy_url_from_entry(entry):
    """把 config.json 的一筆代理轉成 requests 用的 URL；不適用則回 None。

    SOCKS5 用 ``socks5h`` (由代理端解析 DNS)，避免本機 DNS 被轉址規則
    或 RPZ 影響。密碼以 DPAPI 解密，解密失敗視為無密碼 (可能設定的來源
    是別台機器)。型別不支援、欄位缺失一律回 None，由呼叫端略過。
    """
    try:
        ptype = str(entry.get("type", "SOCKS5")).upper()
        if ptype not in ("SOCKS5", "HTTP"):
            return None
        host = str(entry.get("ip", "") or "").strip()
        port = int(entry.get("port") or 0)
        if not host or not port:
            return None
        user = entry.get("user") or ""
        pwd = entry.get("pass") or ""
        if pwd:
            try:
                import secure_config  # 延後載入：保持本模組可獨立測試
                pwd = secure_config.decrypt_password(pwd)
            except Exception:  # noqa: BLE001
                pwd = ""
        scheme = "socks5h" if ptype == "SOCKS5" else "http"
        if user or pwd:
            auth = "{}:{}".format(quote(str(user), safe=""), quote(str(pwd), safe=""))
            return "{}://{}@{}:{}".format(scheme, auth, host, port)
        return "{}://{}:{}".format(scheme, host, port)
    except Exception:  # noqa: BLE001
        return None


def load_proxy_urls(config_paths=None):
    """從 config.json 讀出可用代理，回傳 ``[{"name", "url"}]``。

    任何問題 (檔案不存在、JSON 破損、欄位不合法、密碼解不開) 都只是略過
    該筆；整體失敗時回傳空清單 —— 更新流程絕不因設定檔問題而中斷。
    """
    for path in (config_paths or _config_search_paths()):
        data = None
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
        except Exception:  # noqa: BLE001
            data = None
        if not isinstance(data, dict):
            continue
        out = []
        for entry in (data.get("proxies") or []):
            if not isinstance(entry, dict):
                continue
            url = _proxy_url_from_entry(entry)
            if url:
                out.append({"name": entry.get("name") or url, "url": url})
        if out:
            return out
    return []


def _config_flag(key, default=False, config_paths=None):
    """從 config.json 頂層讀一個布林開關。

    任何問題（檔案不存在、JSON 破損、型別不對）都回 ``default`` —— 與
    :func:`load_proxy_urls` 同一原則：更新流程絕不因設定檔問題而中斷。
    字串寫法 ``"true"`` / ``"yes"`` / ``"on"`` / ``"1"`` 也算真。
    """
    for path in (config_paths or _config_search_paths()):
        try:
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(data, dict) and key in data:
            value = data[key]
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return bool(value)
    return bool(default)


def _total_from_range_headers(headers, status_code):
    """從 (Range) 回應標頭取出檔案總大小；0 表示未知。

    ``_probe_download`` 與 ``_measure_path_detailed`` 都要這個判斷，抽出來
    避免兩份實作對「206 但沒有 content-range」之類的邊界給出不同答案。
    """
    if status_code == 206:
        m = re.search(r"/(\d+)\s*$", headers.get("content-range", "") or "")
        if m:
            return int(m.group(1))
    return int(headers.get("content-length", 0) or 0)


# 伺服器「明確拒絕」Range 請求的狀態碼。實測 http.speed.hinet.net 就是這種：
# 回應標頭宣告 ``Accept-Ranges: bytes``，但任何 Range 請求（連 ``bytes=0-0``
# 都算）都回 416 —— 宣告與行為不一致。這種伺服器只能整檔抓。
_RANGE_REJECT_CODES = (400, 416, 501)


def _range_rejected(status_code):
    """伺服器是否明確**拒絕** Range 請求（而不是忽略它、回整份 200）。"""
    return status_code in _RANGE_REJECT_CODES


def _get_allow_range_fallback(url, headers, proxy_url, timeout):
    """送出請求；若伺服器拒絕 Range，拿掉 Range 標頭重送一次。

    回傳 ``(response, used_range, t_issued)``；``t_issued`` 是最後一次請求真正
    送出的時間（供呼叫端算 TTFB），呼叫端負責關閉 response。

    沒有這層退路時，一個「宣告 Accept-Ranges 卻回 416」的伺服器會讓
    ``_probe_download`` 直接拋例外，於是 ``_download_over_path`` 根本走不到
    它自己的單線備援 —— 整個下載 0.02 秒就失敗，而 curl 抓同一個 URL 完全正常
    （實測 http.speed.hinet.net/test_040m.zip）。
    """
    t = time.monotonic()
    r = requests.get(url, headers=headers, stream=True,
                     proxies=_proxy_map(proxy_url),
                     timeout=(_TIMEOUT_CONNECT, timeout),
                     allow_redirects=True)
    if not _range_rejected(r.status_code):
        return r, True, t
    r.close()
    plain = {k: v for k, v in headers.items() if k.lower() != "range"}
    t = time.monotonic()
    r = requests.get(url, headers=plain, stream=True,
                     proxies=_proxy_map(proxy_url),
                     timeout=(_TIMEOUT_CONNECT, timeout),
                     allow_redirects=True)
    return r, False, t


def _measure_path_detailed(url, proxy_url, timeout=PROXY_PROBE_TIMEOUT,
                           seconds=PROXY_PROBE_SECONDS,
                           max_bytes=PROXY_PROBE_MAX_BYTES):
    """量測一條路徑的吞吐；回傳 ``(speed_bps|None, info dict)``。

    分兩段計時，把「連線 / 302 轉址 / TTFB」排除在分母之外：

        t0 ──(握手、轉址、TTFB)──▶ 首個 chunk ──(量測視窗)──▶ 結束
                                    └─── 只有這段算吞吐 ───┘

    舊版從 t0 起算，於是 256 KB 的探針實際上量到的是 ``1 / TTFB``：
    實測 GitHub 資產 TTFB 約 970 毫秒，而 256 KB 在 300 Mbps 上只帶 21 毫秒，
    回報值低估約 100 倍（119 Mbps 的線被量成 1.1 Mbps），選路等於擲骰子。

    例外是「整個檔都抓完了」的情形：那時回報的是**含 TTFB 的牆鐘**速度。
    因為完整傳輸的端到端時間才是使用者實際感受到的數字，而小檔案若用穩定態
    會反過來高估高 TTFB 的路徑。

    無法量測時回 ``(None, info)``，``info["error"]`` 說明原因 —— 舊版把原因
    全吞掉，於是「代理一直沒被選上」看不出來是代理掛了、還是根本沒送 SOCKS。
    另外帶回 ``final_url`` / ``total`` / ``supports_range``，讓同一條路徑的
    下載階段可以直接沿用這次探針的結果，不必再付一次 TTFB。
    """
    headers = {
        "Range": "bytes=0-{}".format(max_bytes - 1),
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
    }
    info = {"ttfb": None, "bytes": 0, "elapsed": 0.0, "error": None,
            "final_url": None, "total": 0, "supports_range": False,
            "speed": None}
    r = None
    try:
        r, used_range, t0 = _get_allow_range_fallback(
            url, headers, proxy_url, timeout)
        if r.status_code not in (200, 206):
            info["error"] = "HTTP {}".format(r.status_code)
            return None, info
        # 這次探針本來就會跟完轉址、也拿得到回應標頭，於是「轉址後的最終網址」
        # 與「檔案總大小」是免費的副產品。記下來給下載階段重用，同一條路徑就
        # 不必再付一次完整 TTFB（實測 1.7~2.1 秒，佔 34 MB 資產牆鐘的 36~48%）。
        info["final_url"] = r.url or url
        info["supports_range"] = bool(used_range and r.status_code == 206)
        info["total"] = _total_from_range_headers(r.headers, r.status_code)

        chunks = r.iter_content(CHUNK_SIZE)
        first = None
        for chunk in chunks:
            if chunk:
                first = chunk
                break
        if not first:
            info["error"] = "無資料"
            return None, info

        t_first = time.monotonic()
        info["ttfb"] = t_first - t0
        got = len(first)
        capped = got >= max_bytes      # 首個 chunk 就撞到上限（極快的線才可能）
        for chunk in chunks:
            if not chunk:
                continue
            got += len(chunk)
            if got >= max_bytes:
                capped = True
                break
            if time.monotonic() - t_first >= seconds:
                break
        elapsed = time.monotonic() - t_first
        info["bytes"] = got
        info["elapsed"] = elapsed
        complete = bool(info["total"]) and got >= info["total"]
        if complete:
            # 整個檔都抓完了，這是完整樣本。此時要用**含 TTFB 的牆鐘**，不能用
            # 穩定態：小檔案用穩定態會把「TTFB 高但吞吐大」的代理誤判成最快
            # （實測 0.5 MB 在 95 Mbps 直連上，穩定態算出 262 Mbps，但端到端
            # 0.33 秒其實比代理的 1.3 秒快得多）。
            wall = time.monotonic() - t0
            if wall <= 0:
                info["error"] = "無法計時"
                return None, info
            speed = got / wall
            info["speed"] = speed
            return speed, info
        # 走到這裡代表視窗是被 seconds 或位元組上限截斷的。舊版把「資料提早
        # 結束」一律當成樣本不足，於是檔案比「0.3 秒能抓完的量」還小時，明明
        # 整份都抓到了卻被丟棄。實測（exp13，95 Mbps 直連）：0.25 / 0.5 / 1 /
        # 2 MB 全被判樣本不足，4 MB 起才通過 —— 也就是任何小於約 3.5 MB 的
        # 資產，都會讓所有快路徑一起變成不可用，選路只剩 speed=0.0 的直連
        # 保底，代理永遠選不上（正是「每次都選不到快線」的成因之一）。
        if not capped and elapsed < PROXY_PROBE_MIN_SECONDS:
            info["error"] = "樣本不足 {:.2f}s".format(elapsed)
            return None, info
        if elapsed <= 0:
            info["error"] = "樣本不足 0.00s"
            return None, info
        speed = got / elapsed
        info["speed"] = speed
        return speed, info
    except Exception as e:  # noqa: BLE001 — 代理掛掉/逾時都只代表這條不可用
        info["error"] = "{}: {}".format(type(e).__name__, e)
        return None, info
    finally:
        if r is not None:
            try:
                r.close()
            except Exception:  # noqa: BLE001
                pass


def _measure_path(url, proxy_url, timeout=PROXY_PROBE_TIMEOUT,
                  seconds=PROXY_PROBE_SECONDS,
                  max_bytes=PROXY_PROBE_MAX_BYTES):
    """量測一條路徑的穩定吞吐 (bytes/s)；失敗或無資料回 None。"""
    speed, _info = _measure_path_detailed(
        url, proxy_url, timeout, seconds, max_bytes)
    return speed


def _measure_aggregate_throughput(final_url, total, proxy_url, n,
                                  seconds=ADAPTIVE_PROBE_SECONDS,
                                  max_bytes=PROXY_PROBE_MAX_BYTES):
    """同時開 ``n`` 條連線，量「同一段時間內合計抓回多少位元組」。

    回傳 ``(bytes_per_sec|None, ttfb|None, reason)``；量不到時第一個值為 None。
    三個設計要點都是實測踩出來的：

    1. **共同視窗**。每條連線要各自等回應標頭，TTFB 可以差 0.2 秒以上，所以
       不能各算各的起點（那會讓先開始的那條被算得偏快）。這裡用一道 gate：
       全部連線都拿到首個 chunk 之後，才一起開始計時。
    2. **每條連線從不同偏移起讀**（``i * total / n``），且各自有**位元組上限**
       ``min(max_bytes, total // n)``。上限一定 ≤ 每條能分到的區間，所以不會
       有哪條先撞到檔尾而提早收工、把吞吐算低。
    3. **位元組上限是必要的**。沒有它，快路徑會在視窗內把整個檔抓完，量到的
       其實是「檔案大小 ÷ 視窗」——exp22 就是這樣讀出一個假的 2.01×
       （34 MB ÷ 1.5 s = 182.8 Mbps，連續三輪一字不差）。

    注意這是**聚合**量測：若各連線先後撞到上限，先完成的那條會閒置，於是
    聚合值偏**低**。偏差方向是保守的（只會讓我們少開連線），可以接受。
    """
    n = max(1, int(n))
    if total <= 0 or total < n:
        return None, None, "檔案大小未知或不足以分段"
    step = total // n
    per_cap = max(1, min(int(max_bytes), step))
    if per_cap < 256 * 1024:
        return None, None, "每段可分到的區間太小"

    lock = threading.Lock()
    gate = threading.Event()
    ready = threading.Semaphore(0)
    spans = []
    agg = {"bytes": 0, "capped": False, "errors": [], "ttfb": []}

    def worker(i):
        start = i * step
        headers = {
            "Range": "bytes={}-".format(start),
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
        }
        r = None
        try:
            t_issue = time.monotonic()
            r = requests.get(final_url, headers=headers, stream=True,
                             proxies=_proxy_map(proxy_url),
                             timeout=(_TIMEOUT_CONNECT, _TIMEOUT_READ),
                             allow_redirects=True)
            if r.status_code not in (200, 206):
                raise RuntimeError("HTTP {}".format(r.status_code))
            chunks = r.iter_content(CHUNK_SIZE)
            first = None
            for chunk in chunks:
                if chunk:
                    first = chunk
                    break
            if not first:
                raise RuntimeError("無資料")
            with lock:
                agg["ttfb"].append(time.monotonic() - t_issue)
            ready.release()
            if not gate.wait(timeout=_TIMEOUT_CONNECT):
                raise RuntimeError("等待共同視窗逾時")
            t0 = time.monotonic()
            deadline = t0 + seconds
            got = len(first)
            capped = got >= per_cap
            if not capped:
                for chunk in chunks:
                    if not chunk:
                        continue
                    got += len(chunk)
                    if got >= per_cap:
                        capped = True
                        break
                    if time.monotonic() >= deadline:
                        break
            with lock:
                agg["bytes"] += got
                agg["capped"] = agg["capped"] or capped
                spans.append((t0, time.monotonic()))
        except Exception as e:  # noqa: BLE001 — 單條連線失敗只代表這次量不到
            with lock:
                agg["errors"].append("{}: {}".format(type(e).__name__, e))
            try:
                ready.release()
            except Exception:  # noqa: BLE001
                pass
        finally:
            if r is not None:
                try:
                    r.close()
                except Exception:  # noqa: BLE001
                    pass

    workers = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(n)]
    for t in workers:
        t.start()
    deadline = time.monotonic() + PROXY_PROBE_TIMEOUT + 2.0
    arrived = 0
    while arrived < n:
        if not ready.acquire(timeout=max(0.0, deadline - time.monotonic())):
            break
        arrived += 1
    gate.set()
    # gate 開了之後，就緒的連線會在 seconds 內收工。還在等標頭的那些是
    # daemon 執行緒，逾時就放生（它們自己會撞上 _TIMEOUT_READ 而結束）。
    for t in workers:
        t.join(timeout=seconds + 3.0)

    if arrived < n or not spans:
        if agg["errors"]:
            return None, None, agg["errors"][0]
        return None, None, "只有 {} 條連線就緒".format(arrived)
    elapsed = max(s[1] for s in spans) - min(s[0] for s in spans)
    if elapsed <= 0:
        return None, None, "無法計時"
    ttfb = max(agg["ttfb"]) if agg["ttfb"] else None
    return agg["bytes"] / elapsed, ttfb, None


def _adaptive_threads(final_url, total, proxy_url, base_threads, probe_info):
    """決定這次要用幾條連線。回傳 ``(threads, 說明)``。

    基準是**單連線**的吞吐 ``bw1``——選路階段（:func:`_rank_download_paths`）
    已經量過，免費。試探時比較 ``k`` 條連線的**聚合**吞吐，只有**吞吐明顯
    變好、而且延遲沒變差**才採用多連線。

    延遲那一條是 Vegas / FAST 那一類的做法：加連線若讓連線延遲上升，代表
    只是把資料塞進同一個佇列，並沒有真的變快。實測這條 5G 路徑上「連線 +
    TTFB」會從 1.11 秒（1 條）漲到 1.27 秒（8 條），而聚合吞吐沒漲
    （236 → 240 Mbps）——正是過度連線。延遲的雜訊遠比吞吐小，所以拿它當煞車。

    只在**有證據**時才改變行為：

    ==========================================  ====================
    情況                                        採用的連線數
    ==========================================  ====================
    沒有基準值（沒量到 bw1）                     沿用 ``base``（無證據不動）
    檔案太小／估計下載時間太短，不試探           沿用 ``base``（尊重設定值）
    試探成功，吞吐 ≥ K 倍且延遲沒變差            用 ``k``
    試探成功，但吞吐沒明顯變好                   **退回 1 條**
    試探失敗（連不上／逾時）                     沿用 ``base``
    ==========================================  ====================
    """
    base = max(1, int(base_threads))
    info = probe_info or {}
    bw1 = info.get("speed")
    if bw1 is None and info.get("elapsed"):
        bw1 = info["bytes"] / info["elapsed"]
    if base <= 1 or not final_url or not total or not bw1:
        return base, "無基準值，沿用預設 {} 條".format(base)
    if total < ADAPTIVE_MIN_BYTES:
        return base, "檔案僅 {:.1f} MB，不值得試探".format(total / 1048576.0)
    ttfb1 = info.get("ttfb") or 0.0
    est = ttfb1 + total / bw1
    if est < ADAPTIVE_MIN_EST_SECONDS:
        return base, "估計僅 {:.1f}s，試探成本划不來".format(est)
    k = min(base, ADAPTIVE_PROBE_THREADS)
    if k <= 1:
        return base, "沒有可試探的連線數"
    bw_k, ttfb_k, reason = _measure_aggregate_throughput(
        final_url, total, proxy_url, k)
    if not bw_k:
        return base, "試探失敗（{}），沿用預設 {} 條".format(reason, base)
    gain = bw_k / bw1
    lat = (ttfb_k / ttfb1) if (ttfb_k and ttfb1) else 1.0
    if gain >= ADAPTIVE_GAIN and lat <= ADAPTIVE_LATENCY_TOLERANCE:
        return k, "試探 {} 條：吞吐 {:.2f}x、延遲 {:.2f}x → 採用".format(k, gain, lat)
    return 1, ("試探 {} 條：吞吐 {:.2f}x、延遲 {:.2f}x → 退回單連線"
               .format(k, gain, lat))


def _rank_download_paths(url, use_proxy=True, log_cb=None):
    """並行量測直連與各代理，回傳由快到慢的
    ``[(proxy_url, speed, label, info)]``。``info`` 是該路徑的探針細節
    （含 ``final_url`` / ``total`` / ``supports_range``），讓下載階段可以
    直接沿用這次探針，不必為了拿這三個值再付一次 TTFB。

    防呆保證：
    - 沒有設定代理時直接回 ``[(None, 0.0, DIRECT_LABEL, {})]``，不增加延遲。
    - 個別路徑量測失敗 (連不上、不支援、逾時) 只會少一個候選。
    - 直連永遠保留且保底排在最後，代理全掛時行為與原本完全相同。
    """
    proxies = []
    if use_proxy:
        try:
            proxies = load_proxy_urls()
        except Exception:  # noqa: BLE001
            proxies = []
    if not proxies:
        return [(None, 0.0, DIRECT_LABEL, {})]

    candidates = [(p["url"], p["name"]) for p in proxies]
    candidates.append((None, DIRECT_LABEL))

    results = {}
    failures = {}
    lock = threading.Lock()

    def probe(proxy_url, label):
        speed, info = _measure_path_detailed(url, proxy_url)
        with lock:
            if speed is not None:
                results[proxy_url] = (speed, label, info)
            else:
                failures[label] = info

    threads = [threading.Thread(target=probe, args=(u, n), daemon=True)
               for u, n in candidates]
    for t in threads:
        t.start()
    deadline = time.monotonic() + PROXY_PROBE_TOTAL_TIMEOUT
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))

    with lock:
        ranked = [(u, s, n, i) for u, (s, n, i) in results.items()]
        missed = dict(failures)
    # 逾時沒跑完的候選也要講清楚，否則它會靜默地以 0 分墊底，
    # 看起來像「這條路很慢」，實際上是「根本沒量到」。
    for proxy_url, label in candidates:
        if proxy_url not in results and label not in missed:
            missed[label] = {
                "error": "量測未在 {:.0f} 秒內完成".format(PROXY_PROBE_TOTAL_TIMEOUT),
                "ttfb": None,
            }
    if log_cb is not None and missed:
        # 失敗要發聲：舊版把原因全吞掉，於是「代理一直沒被選上」看不出來是
        # 代理掛了、還是程式根本沒把 SOCKS 送出去。
        for label, info in sorted(missed.items()):
            try:
                log_cb("路徑「{}」量測失敗: {}（TTFB {}）".format(
                    label, info.get("error") or "無資料",
                    "{:.0f} ms".format(info["ttfb"] * 1e3)
                    if info.get("ttfb") else "未取得"))
            except Exception:  # noqa: BLE001 — 記錄不應影響選路
                pass

    ranked.sort(key=lambda item: -item[1])
    if not ranked:
        return [(None, 0.0, DIRECT_LABEL, {})]
    if not any(u is None for u, _s, _n, _i in ranked):
        ranked.append((None, 0.0, DIRECT_LABEL, {}))
    return ranked


# ------------------------------------------------------------------ #
# 下載 (多線程分段 + 進度回報 + 停滯偵測)
# ------------------------------------------------------------------ #
def _cleanup_stale_downloads():
    """清掉先前中斷留下的下載殘檔 (舊版每次重試都留一個在 %TEMP%)。"""
    pattern = os.path.join(tempfile.gettempdir(), "netredir_update_*.zip")
    for path in glob.glob(pattern):
        try:
            os.remove(path)
        except OSError:
            pass


def _probe_download(url, timeout=_TIMEOUT_CHECK, proxy_url=None):
    """以 ``Range: bytes=0-0`` 探測檔案大小與是否支援分段下載。

    回傳 ``(final_url, total_size, supports_range)``。total_size 可能為 0
    (伺服器未提供長度)。final_url 是跟隨轉址後的最終網址 (GitHub 的簽名
    CDN URL)，供後續所有分段共用，省去每段重走一次 302。

    伺服器若**拒絕** Range（見 ``_RANGE_REJECT_CODES``），這裡會自動改用不帶
    Range 的請求，並回報 ``supports_range=False`` —— 呼叫端因此會走單線下載，
    而不是整個失敗。
    """
    headers = {
        "Range": "bytes=0-0",
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
    }
    r, used_range, _t = _get_allow_range_fallback(
        url, headers, proxy_url, timeout)
    try:
        r.raise_for_status()
        final_url = r.url or url
        total = _total_from_range_headers(r.headers, r.status_code)
        return final_url, total, bool(used_range and r.status_code == 206)
    finally:
        r.close()


class _ProgressReporter(threading.Thread):
    """每 0.5 秒算一次速度並回報進度 (避免 worker 每讀一塊就發訊號)。"""

    def __init__(self, callback, total, get_downloaded, get_threads, interval=0.5):
        super().__init__(daemon=True)
        self._cb = callback
        self._total = total
        self._get_downloaded = get_downloaded
        self._get_threads = get_threads
        self._interval = interval
        self._stop = threading.Event()
        self._history = collections.deque()   # (t, bytes) 供滑動視窗計算速度

    def run(self):
        while not self._stop.wait(self._interval):
            self.emit()

    def emit(self):
        if self._cb is None:
            return
        now = time.monotonic()
        cur = self._get_downloaded()
        self._history.append((now, cur))
        while len(self._history) > 1 and now - self._history[0][0] > SPEED_WINDOW:
            self._history.popleft()
        t0, b0 = self._history[0]
        dt = now - t0
        # 以滑動視窗平均取代瞬時速度；夾在 0 以上避免區段重試造成負值
        speed = max(0.0, (cur - b0) / dt) if dt > 0 else 0.0
        try:
            self._cb({
                "downloaded": cur,
                "total": self._total,
                "speed": speed,
                "threads": self._get_threads(),
            })
        except Exception:  # noqa: BLE001 — 進度回報不應影響下載
            pass

    def stop(self):
        self._stop.set()


class _StallWatchdog(threading.Thread):
    """主動停滯偵測：位元組數連續 timeout 秒沒有前進，就設 stop 放棄本次下載。

    為什麼不是「從另一條執行緒關閉連線喚醒讀取」：Windows 上對同一個 socket
    呼叫 shutdown()/close() 並不會取消另一條執行緒正在阻塞的 recv()，讀取仍會
    卡到 socket 逾時才返回（已實測）。因此讓下載有界的是兩件事：
    1) ``_TIMEOUT_READ`` 縮到數十秒 —— 任何阻塞讀取都會自行逾時拋錯，帶動既有
       的重試邏輯接手；
    2) 這個 watchdog 偵測「整體毫無前進」，設 stop 讓 worker 停止重試同一批
       停滯區段，上層據此中止並改走下一條路徑（或回報失敗），而不是無限重試。
    """

    def __init__(self, get_downloaded, is_active, stop, timeout=None,
                 interval=2.0):
        super().__init__(daemon=True)
        self._get_downloaded = get_downloaded
        self._is_active = is_active
        self._stop = stop
        self._timeout = NO_PROGRESS_TIMEOUT if timeout is None else timeout
        self._interval = interval

    def run(self):
        last_bytes = self._get_downloaded()
        last_change = time.monotonic()
        while not self._stop.wait(self._interval):
            cur = self._get_downloaded()
            if cur > last_bytes:
                last_bytes, last_change = cur, time.monotonic()
                continue
            if not self._is_active():
                last_change = time.monotonic()
                continue
            if time.monotonic() - last_change >= self._timeout:
                self._stop.set()
                return

    def stop(self):
        self._stop.set()


def _fetch_block(session, url, start, end, dest, block_bytes, idx, lock,
                 stop, cancel_event):
    """下載 [start, end] 這段並寫入 dest 的對應偏移。失敗丟例外由 worker 重試。"""
    headers = {
        "Range": "bytes={}-{}".format(start, end),
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
    }
    r = session.get(url, headers=headers, stream=True,
                    timeout=(_TIMEOUT_CONNECT, _TIMEOUT_READ),
                    allow_redirects=True)
    try:
        if r.status_code != 206:
            raise RuntimeError("HTTP {}".format(r.status_code))
        pos = start
        need = end - start + 1
        win_start = time.monotonic()
        win_bytes = 0
        with open(dest, "r+b") as f:
            f.seek(start)
            for chunk in r.iter_content(CHUNK_SIZE):
                if stop.is_set():
                    raise UpdateCancelled()
                if cancel_event is not None and cancel_event.is_set():
                    raise UpdateCancelled()
                if not chunk:
                    continue
                if pos + len(chunk) > end + 1:
                    chunk = chunk[:end + 1 - pos]
                f.write(chunk)
                pos += len(chunk)
                win_bytes += len(chunk)
                with lock:
                    block_bytes[idx] += len(chunk)
                if pos > end:
                    break
                now = time.monotonic()
                if now - win_start >= STALL_WINDOW:
                    if win_bytes < STALL_MIN_BYTES:
                        raise RuntimeError(
                            "停滯: {} bytes/{:.0f}s".format(win_bytes, now - win_start))
                    win_start, win_bytes = now, 0
        if pos - start < need:
            raise RuntimeError("區段不完整: {}/{}".format(pos - start, need))
    finally:
        r.close()


def _download_multipart(final_url, dest, total, threads, progress_cb, cancel_event,
                        proxy_url=None):
    """把檔案切成多段並行下載到 dest (dest 會先配置成 total 大小)。

    段數 = clamp(ceil(total / MIN_BLOCK_SIZE), 1, MAX_BLOCKS)，再受 ``threads``
    限制；worker 執行緒數 = 段數。舊版有兩個問題：
      1. ``threads`` 參數在函式體內完全沒被使用，worker 數直接等於段數，
         於是 DOWNLOAD_THREADS=8 是裝飾品（34 MB 檔實際開 32 條連線）。
      2. 段固定 1 MB，而這條 CDN 每次 Range 請求的回應標頭要等 1.3 秒以上，
         等於 98% 的時間在等固定延遲（見 MIN_BLOCK_SIZE 的實測註解）。
    """
    n = max(1, min(int(threads), MAX_BLOCKS,
                   (total + MIN_BLOCK_SIZE - 1) // MIN_BLOCK_SIZE))
    block_size = max(1, (total + n - 1) // n)
    bounds = []
    start = 0
    while start < total:
        end = min(start + block_size, total) - 1
        bounds.append((start, end))
        start = end + 1
    if not bounds:
        bounds = [(0, total - 1)]
    n = len(bounds)

    with open(dest, "wb") as f:
        f.truncate(total)

    work = queue.Queue()
    for i in range(n):
        work.put(i)

    lock = threading.Lock()
    block_bytes = [0] * n
    active = [0]
    stop = threading.Event()
    failures = []

    def downloaded():
        with lock:
            return sum(block_bytes)

    def active_count():
        with lock:
            return active[0]

    reporter = _ProgressReporter(progress_cb, total, downloaded, active_count)
    reporter.start()
    watchdog = _StallWatchdog(downloaded, active_count, stop)
    watchdog.start()

    def worker():
        session = requests.Session()
        if proxy_url:
            session.proxies.update(_proxy_map(proxy_url))
        try:
            while not stop.is_set():
                if cancel_event is not None and cancel_event.is_set():
                    stop.set()
                    return
                try:
                    idx = work.get_nowait()
                except queue.Empty:
                    return
                b_start, b_end = bounds[idx]
                with lock:
                    active[0] += 1
                try:
                    attempt = 0
                    while not stop.is_set():
                        attempt += 1
                        try:
                            _fetch_block(session, final_url, b_start, b_end, dest,
                                         block_bytes, idx, lock, stop, cancel_event)
                            break
                        except UpdateCancelled:
                            stop.set()
                            return
                        except Exception as e:  # noqa: BLE001
                            if cancel_event is not None and cancel_event.is_set():
                                stop.set()
                                return
                            if attempt >= MAX_BLOCK_RETRIES:
                                failures.append(
                                    "區段 {}-{} 失敗: {}".format(b_start, b_end, e))
                                stop.set()
                                return
                            # 重試前把該段已計入的位元組歸零，進度才不會虛胖
                            with lock:
                                block_bytes[idx] = 0
                            time.sleep(min(5.0, 0.5 * (2 ** (attempt - 1))))
                finally:
                    with lock:
                        active[0] -= 1
        finally:
            session.close()

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(n)]
    for t in workers:
        t.start()

    # 正常情況 worker 會自然結束。真的停滯時 watchdog 會設 stop；被阻塞在
    # read() 的 worker 則靠 _TIMEOUT_READ 自行逾時退出（Windows 無法從外部
    # 取消阻塞的 recv）。這裡是最後保險：stop 設起卻仍有執行緒存活時，最多再
    # 等 STOP_GRACE 秒就放棄，絕不無限等待。
    grace_deadline = None
    for t in workers:
        while True:
            t.join(timeout=0.5)
            if not t.is_alive():
                break
            if stop.is_set():
                if grace_deadline is None:
                    grace_deadline = time.monotonic() + STOP_GRACE
                elif time.monotonic() >= grace_deadline:
                    break

    alive = any(t.is_alive() for t in workers)
    stop.set()
    watchdog.stop()
    reporter.emit()
    reporter.stop()

    if cancel_event is not None and cancel_event.is_set():
        raise UpdateCancelled()
    if failures:
        raise RuntimeError(failures[0])
    if alive:
        raise RuntimeError("下載執行緒停滯且未能結束，已中止")
    if os.path.getsize(dest) != total or downloaded() < total:
        raise RuntimeError(
            "下載不完整: {}/{} 位元組".format(downloaded(), total))


def _download_single(final_url, dest, total_hint, progress_cb, cancel_event,
                     proxy_url=None):
    """單線串流下載 (伺服器不支援 Range，或分段失敗時的後備路徑)。"""
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    stop = threading.Event()
    r = requests.get(final_url, headers=headers, stream=True,
                     timeout=(_TIMEOUT_CONNECT, _TIMEOUT_READ),
                     allow_redirects=True, proxies=_proxy_map(proxy_url))
    done_holder = [0]
    watchdog = _StallWatchdog(lambda: done_holder[0], lambda: True, stop)
    watchdog.start()
    try:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0) or 0) or total_hint
        done = 0
        last_t = time.monotonic()
        last_b = 0
        win_start = time.monotonic()
        win_bytes = 0
        with open(dest, "wb") as f:
            for chunk in r.iter_content(CHUNK_SIZE):
                if stop.is_set():
                    raise RuntimeError("停滯: 連線無回應")
                if cancel_event is not None and cancel_event.is_set():
                    raise UpdateCancelled()
                if not chunk:
                    continue
                f.write(chunk)
                done += len(chunk)
                done_holder[0] = done
                win_bytes += len(chunk)
                now = time.monotonic()
                if progress_cb is not None and now - last_t >= 0.5:
                    speed = (done - last_b) / (now - last_t) if now > last_t else 0.0
                    try:
                        progress_cb({"downloaded": done, "total": total,
                                     "speed": speed, "threads": 1})
                    except Exception:  # noqa: BLE001
                        pass
                    last_t, last_b = now, done
                if now - win_start >= STALL_WINDOW:
                    if win_bytes < STALL_MIN_BYTES:
                        raise RuntimeError(
                            "停滯: {} bytes/{:.0f}s".format(win_bytes, now - win_start))
                    win_start, win_bytes = now, 0
        if total and done < total:
            raise RuntimeError("下載不完整: {}/{} 位元組".format(done, total))
    finally:
        stop.set()
        watchdog.stop()
        r.close()


def _download_over_path(url, dest, proxy_url, threads, progress_cb,
                        cancel_event, probe_info=None, log_cb=None):
    """用指定路徑 (proxy_url 為 None 表示直連) 完成一次下載。

    ``probe_info`` 是選路階段對同一條路徑的探針結果。帶著它就能沿用已經付過
    的那次 TTFB（取得轉址後網址與檔案大小），省掉一次多餘的
    ``Range: bytes=0-0`` —— 實測那一次要 1.7~2.1 秒，是 34 MB 資產牆鐘時間的
    36~48%。缺漏或不可用時退回自行探測，行為與舊版完全相同。

    ``ADAPTIVE_CONCURRENCY``（或 config.json 的 ``adaptive_concurrency``）打開
    時，會先用 :func:`_adaptive_threads` 決定實際連線數；關閉時 ``threads``
    直接照用，行為與舊版一模一樣。
    """
    info = probe_info or {}
    final_url = info.get("final_url")
    total = int(info.get("total") or 0)
    supports_range = bool(info.get("supports_range"))
    if not final_url or not total:
        probed = _probe_download(url, proxy_url=proxy_url)
        final_url, total, supports_range = probed

    if supports_range and total >= MIN_MULTIPART_SIZE:
        eff_threads = max(1, int(threads))
        if ADAPTIVE_CONCURRENCY or _config_flag(ADAPTIVE_CONCURRENCY_KEY):
            eff_threads, why = _adaptive_threads(
                final_url, total, proxy_url, eff_threads, info)
            if log_cb is not None:
                try:
                    log_cb("自適應連線數：{}".format(why))
                except Exception:  # noqa: BLE001 — 記錄不應影響下載
                    pass
        try:
            _download_multipart(final_url, dest, total, eff_threads,
                                progress_cb, cancel_event, proxy_url=proxy_url)
            return
        except UpdateCancelled:
            raise
        except Exception:  # noqa: BLE001 — 分段失敗退回單線再試
            if cancel_event is not None and cancel_event.is_set():
                raise UpdateCancelled()

    last_error = None
    for attempt in range(1, MAX_BLOCK_RETRIES + 1):
        if cancel_event is not None and cancel_event.is_set():
            raise UpdateCancelled()
        # 每次重試都重新探測：GitHub 的簽名 URL 有時效，沿用舊 URL 會 403
        try:
            fresh_url, fresh_total, _ = _probe_download(url, proxy_url=proxy_url)
            if fresh_url:
                final_url = fresh_url
            if fresh_total:
                total = fresh_total
        except Exception:  # noqa: BLE001 — 探測失敗就沿用既有 URL 再試
            pass
        try:
            _download_single(final_url, dest, total, progress_cb, cancel_event,
                             proxy_url=proxy_url)
            return
        except UpdateCancelled:
            raise
        except Exception as e:  # noqa: BLE001
            last_error = e
            if attempt < MAX_BLOCK_RETRIES:
                time.sleep(min(5.0, 0.5 * (2 ** (attempt - 1))))
    raise RuntimeError("下載失敗: {}".format(last_error))


def download_file(url, dest, progress_cb=None, cancel_event=None,
                  threads=DOWNLOAD_THREADS, use_proxy=True, log_cb=None):
    """下載 url 到 dest，具備多線程分段、進度回報、停滯偵測與取消。

    會先實測「直連 + config.json 內設定的代理」各條路徑的吞吐，挑最快的一條
    下載；該路徑中途失敗時自動改用次快的，最後保底直連。找不到代理、或代理
    全部不可用時，行為與純直連完全相同 (防呆)。

    選路時的探針會一併帶回「轉址後網址」與「檔案大小」，下載階段直接沿用，
    因此同一條路徑不會被探測兩次（省下的那一次約 1.7~2.1 秒，佔 34 MB 資產
    牆鐘時間的 36~48%）。

    ``progress_cb`` 會收到 dict: ``{"downloaded", "total", "speed", "threads"}``；
    ``cancel_event`` 為 ``threading.Event``，設起後會盡快中止並拋出
    :class:`UpdateCancelled`；``log_cb`` 收到字串訊息，供 UI 顯示選路結果。
    """
    if cancel_event is not None and cancel_event.is_set():
        raise UpdateCancelled()

    ranked = _rank_download_paths(url, use_proxy=use_proxy, log_cb=log_cb)

    if log_cb is not None:
        try:
            log_cb("更新下載候選路徑（由快到慢）: {}".format(
                " > ".join("{} {:.2f} MB/s".format(lbl, sp / 1048576)
                           for _u, sp, lbl, _i in ranked)))
        except Exception:  # noqa: BLE001
            pass

    last_error = None
    for proxy_url, speed, label, probe_info in ranked:
        if cancel_event is not None and cancel_event.is_set():
            raise UpdateCancelled()
        if log_cb is not None:
            try:
                log_cb("更新下載路徑: {} ({:.2f} MB/s)".format(
                    label, speed / 1048576))
            except Exception:  # noqa: BLE001 — 記錄不應影響下載
                pass
        try:
            _download_over_path(url, dest, proxy_url, threads,
                                progress_cb, cancel_event,
                                probe_info=probe_info, log_cb=log_cb)
            return
        except UpdateCancelled:
            raise
        except Exception as e:  # noqa: BLE001 — 換下一條路徑再試
            last_error = e
            if log_cb is not None:
                try:
                    log_cb("路徑「{}」失敗，改用下一條: {}".format(label, e))
                except Exception:  # noqa: BLE001
                    pass
    raise RuntimeError("下載失敗: {}".format(last_error))


def stage_update(asset_url, asset_name, checksum_url, timeout=_TIMEOUT_DOWNLOAD,
                 progress_cb=None, cancel_event=None, threads=DOWNLOAD_THREADS,
                 use_proxy=True, log_cb=None):
    """下載並驗證更新，解壓到 <dist>.new，回傳新目錄路徑。

    任何一步失敗都拋例外；下載的暫存檔會在 finally 中清理。
    """
    _cleanup_stale_downloads()

    # 1. 先取 SHA256 清單 (小檔)，解析出本資產的期望雜湊
    r = requests.get(checksum_url, timeout=timeout)
    r.raise_for_status()
    expected = _parse_expected_sha256(r.text, asset_name)
    if not expected:
        raise RuntimeError("SHA256 清單中找不到對應資產的雜湊值，中止更新")

    # 2. 下載 zip 到暫存檔
    fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="netredir_update_")
    os.close(fd)
    try:
        download_file(asset_url, tmp_path, progress_cb=progress_cb,
                      cancel_event=cancel_event, threads=threads,
                      use_proxy=use_proxy, log_cb=log_cb)

        # 3. 校驗 (不符即中止，避免執行被竄改的二進位檔)
        if not verify_sha256(tmp_path, expected):
            raise RuntimeError("下載的更新檔 SHA256 校驗失敗，已中止更新")

        # 4. 解壓到 <dist>.new
        dist_dir = current_dist_dir()
        new_dir = dist_dir + ".new"
        if os.path.exists(new_dir):
            shutil.rmtree(new_dir, ignore_errors=True)
        os.makedirs(new_dir, exist_ok=True)

        with zipfile.ZipFile(tmp_path) as z:
            # 防 zip-slip：解壓前先確認所有目標路徑仍在 new_dir 內
            new_base = os.path.normpath(new_dir) + os.sep
            for m in z.infolist():
                target = os.path.normpath(os.path.join(new_dir, m.filename))
                if not target.startswith(new_base):
                    raise RuntimeError("更新檔包含不安全的解壓路徑，已中止更新")
            z.extractall(new_dir)

        return new_dir
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def _apply_script_content():
    """產生背景替換腳本 (PowerShell)。

    內容保持純 ASCII，避免 PowerShell 5.1 將無 BOM 的 UTF-8 誤讀為 ANSI，
    使中文註解變成亂碼 (甚至造成解析問題)。日誌路徑以參數 $Log 傳入，
    不再依賴 $env:TEMP。
    """
    return r'''param(
    [string]$Dist,
    [string]$NewDir,
    [string]$OldDir,
    [string]$Exe,
    [string]$ExeName,
    [string]$Log
)
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$m) { Add-Content -Path $Log -Value ((Get-Date -Format o) + "  " + $m) -ErrorAction SilentlyContinue }

L ("apply start  Dist=[" + $Dist + "] NewDir=[" + $NewDir + "] OldDir=[" + $OldDir + "] Exe=[" + $Exe + "] ExeName=[" + $ExeName + "]")

# delete-on-reboot support: a running kernel driver locks its .sys image, so
# leftovers are registered with MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) instead.
$sig = @"
using System;
using System.Runtime.InteropServices;
public static class NRNative {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
}
"@
try { Add-Type -TypeDefinition $sig -ErrorAction Stop } catch { }
$MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

function Remove-Path([string]$p) {
    if (-not (Test-Path $p)) { return $true }
    for ($i = 0; $i -lt 10; $i++) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $p)) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Schedule-DeleteOnReboot([string]$root) {
    if (-not (Test-Path $root)) { return }
    $items = @(Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue)
    foreach ($it in ($items | Sort-Object { $_.FullName.Length } -Descending)) {
        [NRNative]::MoveFileEx($it.FullName, $null, $MOVEFILE_DELAY_UNTIL_REBOOT) | Out-Null
    }
    [NRNative]::MoveFileEx($root, $null, $MOVEFILE_DELAY_UNTIL_REBOOT) | Out-Null
}

function Stop-WinDivert {
    $any = $false
    try {
        $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
            Where-Object { $_.Name -like 'WinDivert*' -and $_.State -eq 'Running' })
        foreach ($d in $drivers) {
            & sc.exe stop $d.Name | Out-Null
            L ("driver stop requested: " + $d.Name)
            $any = $true
        }
    } catch { }
    if ($any) { Start-Sleep -Seconds 2 }
    return $any
}

# 1. wait for the app to fully exit (name without .exe)
while (Get-Process -Name $ExeName -ErrorAction SilentlyContinue) { Start-Sleep -Seconds 1 }
L "app exited"

# 2. stop the WinDivert kernel driver so its .sys image is unlocked
Stop-WinDivert | Out-Null

# 3. clear leftover old dir; if it is still locked, move it aside so it can no
#    longer block the rename below (a stale ".old" is what caused stuck updates).
$staleDirs = @()
$lockedOld = $null
if (Remove-Path $OldDir) {
    L "old cleared"
} else {
    $lockedOld = $OldDir
    Schedule-DeleteOnReboot $lockedOld
    $stale = $OldDir + ".stale." + (Get-Date -Format 'yyyyMMddHHmmss')
    Rename-Item $OldDir $stale -Force -ErrorAction SilentlyContinue
    if (Test-Path $stale) {
        $staleDirs += $stale
        $lockedOld = $stale
        L ("old locked; moved aside to [" + $stale + "]")
    } else {
        $OldDir = $OldDir + "." + (Get-Date -Format 'yyyyMMddHHmmss')
        L ("old locked and could not be moved; swap target=[" + $OldDir + "]")
    }
}

# 4. swap: Dist -> OldDir, NewDir -> Dist. Success means NewDir is consumed and
#    Dist exists, NOT merely that some exe is present (the old one always was).
$ok = $false
for ($i = 0; $i -lt 15 -and -not $ok; $i++) {
    if ((Test-Path $Dist) -and (Test-Path $NewDir) -and -not (Test-Path $OldDir)) {
        Rename-Item $Dist $OldDir -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path $NewDir) -and -not (Test-Path $Dist)) {
        Rename-Item $NewDir $Dist -Force -ErrorAction SilentlyContinue
    }
    if ((-not (Test-Path $NewDir)) -and (Test-Path $Dist) -and (Test-Path $Exe)) {
        $ok = $true
    } else {
        Start-Sleep -Seconds 1
    }
}
L ("swap ok=" + $ok)

# 5. preserve runtime data (config, vpn history)
foreach ($f in @('config.json','vpn_history.json')) {
    $src = Join-Path $OldDir $f
    if ((Test-Path $src) -and (Test-Path $Dist)) { Copy-Item $src (Join-Path $Dist $f) -Force -ErrorAction SilentlyContinue }
}
L "config preserved"

# 6. relaunch the app (fall back to the existing install if the swap failed)
if (Test-Path $Exe) {
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.WorkingDirectory = $Dist
        $psi.UseShellExecute = $false
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        L ("restart OK  (swap=" + $ok + ")")
    } catch {
        L ("restart FAIL: " + $_)
    }
} else {
    L ("restart skipped  (swap=" + $ok + ", exe missing)")
}

# 7. cleanup old version(s); anything still locked is removed on next reboot
$cleanupTargets = @($OldDir) + $staleDirs
if ($lockedOld -and ($cleanupTargets -notcontains $lockedOld)) { $cleanupTargets += $lockedOld }
foreach ($d in $cleanupTargets) {
    if ($d -and (Test-Path $d)) {
        $cleaned = Remove-Path $d
        if (-not $cleaned) { Schedule-DeleteOnReboot $d }
        L ("cleanup [" + $d + "] done=" + $cleaned)
    }
}

L "apply done"
'''


def apply_and_restart():
    """寫入並啟動背景替換腳本；呼叫端須隨後優雅關閉主程式。

    僅在打包後的可執行檔中允許 (開發模式直接丟例外，避免誤動 repo 目錄)。
    """
    if not is_frozen():
        raise RuntimeError("自動更新的套用/替換步驟僅支援打包後的可執行檔（目前偵測為原始碼/開發模式執行）")

    dist_dir = current_dist_dir()
    exe_path = _frozen_exe_path()
    exe_base = os.path.basename(exe_path)          # 例如 IntegratedApp.exe
    exe_name = os.path.splitext(exe_base)[0]       # Get-Process 需去掉 .exe
    new_dir = dist_dir + ".new"
    old_dir = dist_dir + ".old"
    install_dir = os.path.dirname(dist_dir)

    script_path = os.path.join(install_dir, "apply_update.ps1")
    log_path = os.path.join(install_dir, "update_apply.log")
    err_path = os.path.join(install_dir, "update_apply_err.log")

    # 以 UTF-8 BOM 寫入，確保 PowerShell 5.1 正確辨識編碼
    with open(script_path, "w", encoding="utf-8-sig") as f:
        f.write(_apply_script_content())

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # stderr 導到獨立檔案，捕捉 powershell 本身的解析/執行錯誤
    with open(err_path, "ab") as err_fd:
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", script_path,
             "-Dist", dist_dir, "-NewDir", new_dir, "-OldDir", old_dir,
             "-Exe", exe_path, "-ExeName", exe_name, "-Log", log_path],
            cwd=install_dir,
            creationflags=creationflags,
            stdout=subprocess.DEVNULL,
            stderr=err_fd,
        )
