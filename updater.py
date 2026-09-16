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

import glob
import hashlib
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

import requests

from version import UPDATE_API_URL

_TIMEOUT_CHECK = 15       # 檢查更新 (API) 逾時秒數
_TIMEOUT_CONNECT = 15     # 建立連線逾時秒數
_TIMEOUT_READ = 60        # 單次讀取逾時秒數 (超過此時間沒收到資料視為斷線)
_TIMEOUT_DOWNLOAD = 180   # SHA256 清單等下載的逾時秒數

# --- 多線程分段下載參數 ---
DOWNLOAD_THREADS = 8                  # 預設並行連線數
TARGET_BLOCK_SIZE = 4 * 1024 * 1024   # 目標分段大小 (依檔案大小決定段數)
MAX_BLOCKS = 16                       # 分段數上限
MIN_MULTIPART_SIZE = 4 * 1024 * 1024  # 小於此大小不值得分段，直接單線
CHUNK_SIZE = 256 * 1024               # 每次讀取的位元組數
STALL_WINDOW = 30                     # 停滯偵測視窗 (秒)
STALL_MIN_BYTES = 128 * 1024          # 視窗內至少需收到的位元組，否則視為停滯
MAX_BLOCK_RETRIES = 4                 # 單一分段最大重試次數
USER_AGENT = "NetRedirector-Updater"


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


def _probe_download(url, timeout=_TIMEOUT_CHECK):
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
                     stream=True, allow_redirects=True)
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
        self._last_bytes = 0
        self._last_time = None

    def run(self):
        while not self._stop.wait(self._interval):
            self.emit()

    def emit(self):
        if self._cb is None:
            return
        now = time.monotonic()
        cur = self._get_downloaded()
        if self._last_time is None:
            self._last_time, self._last_bytes = now, cur
        dt = now - self._last_time
        speed = (cur - self._last_bytes) / dt if dt > 0 else 0.0
        self._last_time, self._last_bytes = now, cur
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


def _download_multipart(final_url, dest, total, threads, progress_cb, cancel_event):
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

    def worker():
        session = requests.Session()
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
                    while True:
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
    for t in workers:
        t.join()

    reporter.emit()
    reporter.stop()

    if cancel_event is not None and cancel_event.is_set():
        raise UpdateCancelled()
    if failures:
        raise RuntimeError(failures[0])
    if os.path.getsize(dest) != total or downloaded() < total:
        raise RuntimeError(
            "下載不完整: {}/{} 位元組".format(downloaded(), total))


def _download_single(final_url, dest, total_hint, progress_cb, cancel_event):
    """單線串流下載 (伺服器不支援 Range，或分段失敗時的後備路徑)。"""
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    r = requests.get(final_url, headers=headers, stream=True,
                     timeout=(_TIMEOUT_CONNECT, _TIMEOUT_READ),
                     allow_redirects=True)
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
                if cancel_event is not None and cancel_event.is_set():
                    raise UpdateCancelled()
                if not chunk:
                    continue
                f.write(chunk)
                done += len(chunk)
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
        r.close()


def download_file(url, dest, progress_cb=None, cancel_event=None,
                  threads=DOWNLOAD_THREADS):
    """下載 url 到 dest，具備多線程分段、進度回報、停滯偵測與取消。

    ``progress_cb`` 會收到 dict: ``{"downloaded", "total", "speed", "threads"}``；
    ``cancel_event`` 為 ``threading.Event``，設起後會盡快中止並拋出
    :class:`UpdateCancelled`。
    """
    if cancel_event is not None and cancel_event.is_set():
        raise UpdateCancelled()

    final_url, total, supports_range = _probe_download(url)

    if supports_range and total >= MIN_MULTIPART_SIZE:
        try:
            _download_multipart(final_url, dest, total, max(1, int(threads)),
                                progress_cb, cancel_event)
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
        try:
            _download_single(final_url, dest, total, progress_cb, cancel_event)
            return
        except UpdateCancelled:
            raise
        except Exception as e:  # noqa: BLE001
            last_error = e
            if attempt < MAX_BLOCK_RETRIES:
                time.sleep(min(5.0, 0.5 * (2 ** (attempt - 1))))
    raise RuntimeError("下載失敗: {}".format(last_error))


def stage_update(asset_url, asset_name, checksum_url, timeout=_TIMEOUT_DOWNLOAD,
                 progress_cb=None, cancel_event=None, threads=DOWNLOAD_THREADS):
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
                      cancel_event=cancel_event, threads=threads)

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

# 1. wait for the app to fully exit (name without .exe)
while (Get-Process -Name $ExeName -ErrorAction SilentlyContinue) { Start-Sleep -Seconds 1 }
L "app exited"

# 2. remove leftover old version
if (Test-Path $OldDir) { Remove-Item $OldDir -Recurse -Force -ErrorAction SilentlyContinue }
L "old cleared"

# 3. atomic swap: Dist -> OldDir, NewDir -> Dist (retry for file unlock)
$ok = $false
for ($i = 0; $i -lt 15 -and -not $ok; $i++) {
    if ((Test-Path $Dist) -and (Test-Path $NewDir)) { Rename-Item $Dist $OldDir -Force -ErrorAction SilentlyContinue }
    if ((Test-Path $NewDir) -and -not (Test-Path $Dist)) { Rename-Item $NewDir $Dist -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Exe) { $ok = $true } else { Start-Sleep -Seconds 1 }
}
L ("swap ok=" + $ok)

# 3.5 preserve runtime data (config, vpn history)
foreach ($f in @('config.json','vpn_history.json')) {
    $src = Join-Path $OldDir $f
    if ((Test-Path $src) -and (Test-Path $Dist)) { Copy-Item $src (Join-Path $Dist $f) -Force -ErrorAction SilentlyContinue }
}
L "config preserved"

# 4. relaunch the app
if ($ok) {
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.WorkingDirectory = $Dist
        $psi.UseShellExecute = $false
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        L "restart OK"
    } catch {
        L ("restart FAIL: " + $_)
    }
} else {
    L "restart skipped (swap failed)"
}

# 5. cleanup old version (sync retry; the new app is already relaunching)
if (Test-Path $OldDir) {
    $cleaned = $false
    for ($i = 0; $i -lt 10 -and -not $cleaned; $i++) {
        Remove-Item $OldDir -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $OldDir)) { $cleaned = $true } else { Start-Sleep -Seconds 1 }
    }
    L ("cleanup done=" + $cleaned)
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
