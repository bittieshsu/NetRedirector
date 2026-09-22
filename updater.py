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
DOWNLOAD_THREADS = 8                  # 預設並行連線數
TARGET_BLOCK_SIZE = 1 * 1024 * 1024   # 目標分段大小 (依檔案大小決定段數)
MAX_BLOCKS = 32                       # 分段數上限
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
PROXY_PROBE_BYTES = 256 * 1024        # 量測各路徑吞吐時抓的位元組數
PROXY_PROBE_TIMEOUT = 6               # 單一路徑量測逾時 (秒)
PROXY_PROBE_TOTAL_TIMEOUT = 8         # 全部路徑量測的總逾時 (秒)


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


def _measure_path(url, proxy_url, probe_bytes=PROXY_PROBE_BYTES,
                  timeout=PROXY_PROBE_TIMEOUT):
    """量測一條路徑的吞吐 (bytes/s)；失敗或無資料回 None。

    用一次小範圍 Range 請求實測，而不是只量 ping —— CDN 與代理的「連得上」
    和「跑得快」經常是兩回事，只量延遲會挑到很慢的線。
    """
    headers = {
        "Range": "bytes=0-{}".format(probe_bytes - 1),
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
    }
    try:
        t0 = time.monotonic()
        r = requests.get(url, headers=headers, stream=True,
                         proxies=_proxy_map(proxy_url),
                         timeout=(_TIMEOUT_CONNECT, timeout),
                         allow_redirects=True)
        try:
            if r.status_code not in (200, 206):
                return None
            got = 0
            for chunk in r.iter_content(CHUNK_SIZE):
                if not chunk:
                    continue
                got += len(chunk)
                if got >= probe_bytes:
                    break
            dt = time.monotonic() - t0
            if got <= 0 or dt <= 0:
                return None
            return got / dt
        finally:
            r.close()
    except Exception:  # noqa: BLE001 — 代理掛掉/不支援 SOCKS 都只代表這條不可用
        return None


def _rank_download_paths(url, use_proxy=True):
    """並行量測直連與各代理，回傳由快到慢的 ``[(proxy_url, speed, label)]``。

    防呆保證：
    - 沒有設定代理時直接回 ``[(None, 0.0, "直連")]``，不增加任何延遲。
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
        return [(None, 0.0, "直連")]

    candidates = [(p["url"], p["name"]) for p in proxies]
    candidates.append((None, "直連"))

    results = {}
    lock = threading.Lock()

    def probe(proxy_url, label):
        speed = _measure_path(url, proxy_url)
        if speed is not None:
            with lock:
                results[proxy_url] = (speed, label)

    threads = [threading.Thread(target=probe, args=(u, n), daemon=True)
               for u, n in candidates]
    for t in threads:
        t.start()
    deadline = time.monotonic() + PROXY_PROBE_TOTAL_TIMEOUT
    for t in threads:
        t.join(timeout=max(0.0, deadline - time.monotonic()))

    with lock:
        ranked = [(u, s, n) for u, (s, n) in results.items()]
    ranked.sort(key=lambda item: -item[1])
    if not ranked:
        return [(None, 0.0, "直連")]
    if not any(u is None for u, _, _ in ranked):
        ranked.append((None, 0.0, "直連"))
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
    """
    headers = {
        "Range": "bytes=0-0",
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
    }
    r = requests.get(url, headers=headers, timeout=(_TIMEOUT_CONNECT, timeout),
                     stream=True, allow_redirects=True,
                     proxies=_proxy_map(proxy_url))
    try:
        r.raise_for_status()
        final_url = r.url or url
        if r.status_code == 206:
            total = 0
            m = re.search(r"/(\d+)\s*$", r.headers.get("content-range", ""))
            if m:
                total = int(m.group(1))
            if not total:
                total = int(r.headers.get("content-length", 0) or 0)
            return final_url, total, True
        return final_url, int(r.headers.get("content-length", 0) or 0), False
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
    """把檔案切成多段並行下載到 dest (dest 會先配置成 total 大小)。"""
    block_size = max(TARGET_BLOCK_SIZE, (total + MAX_BLOCKS - 1) // MAX_BLOCKS)
    bounds = []
    start = 0
    while start < total and len(bounds) < MAX_BLOCKS:
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


def _download_over_path(url, dest, proxy_url, threads, progress_cb, cancel_event):
    """用指定路徑 (proxy_url 為 None 表示直連) 完成一次下載。"""
    final_url, total, supports_range = _probe_download(url, proxy_url=proxy_url)

    if supports_range and total >= MIN_MULTIPART_SIZE:
        try:
            _download_multipart(final_url, dest, total, max(1, int(threads)),
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

    ``progress_cb`` 會收到 dict: ``{"downloaded", "total", "speed", "threads"}``；
    ``cancel_event`` 為 ``threading.Event``，設起後會盡快中止並拋出
    :class:`UpdateCancelled`；``log_cb`` 收到字串訊息，供 UI 顯示選路結果。
    """
    if cancel_event is not None and cancel_event.is_set():
        raise UpdateCancelled()

    ranked = _rank_download_paths(url, use_proxy=use_proxy)

    last_error = None
    for proxy_url, speed, label in ranked:
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
                                progress_cb, cancel_event)
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
