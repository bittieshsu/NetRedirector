# -*- coding: utf-8 -*-
"""updater 純邏輯單元測試 — 版本比對 / SHA256 校驗 (不觸及網路)。"""

import hashlib
import http.server
import os
import re
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import updater


def test_parse_semver_strips_v():
    assert updater.parse_semver("v1.7.0") == "1.7.0"
    assert updater.parse_semver("1.7.0") == "1.7.0"
    assert updater.parse_semver("") == ""


def test_version_tuple_ordering():
    # 字串比對會誤判 1.10.0 < 1.9.0，tuple 比對不會
    assert updater._version_tuple("1.10.0") > updater._version_tuple("1.9.0")
    assert updater._version_tuple("1.6.1") == updater._version_tuple("1.6.1")


def test_check_update_none_when_same_or_older(monkeypatch):
    monkeypatch.setattr(
        updater, "get_latest_release",
        lambda *a, **k: {"tag_name": "v1.6.1", "assets": []})
    # 同版本 → None (不會因缺資產而拋錯)
    assert updater.check_update("1.6.1") is None

    monkeypatch.setattr(
        updater, "get_latest_release",
        lambda *a, **k: {"tag_name": "v1.5.0", "assets": []})
    # 較舊 → None
    assert updater.check_update("1.6.1") is None


def test_verify_sha256(tmp_path):
    p = tmp_path / "f.bin"
    data = b"hello netredirector"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert updater.verify_sha256(str(p), expected)
    assert updater.verify_sha256(str(p), expected.upper())  # 大小寫不敏感
    assert not updater.verify_sha256(str(p), "0" * 64)


def test_parse_expected_sha256():
    text = "abc123  NetRedirector-v1.6.2-win64.zip\n"
    assert updater._parse_expected_sha256(text, "NetRedirector-v1.6.2-win64.zip") == "abc123"
    assert updater._parse_expected_sha256(text, "nonexistent.zip") is None


def test_is_frozen_detects_nuitka_compiled(monkeypatch):
    """Nuitka 以 __compiled__ 注入凍結旗標，is_frozen() 必須能辨識。"""
    monkeypatch.setattr(updater, "__compiled__", True, raising=False)
    assert updater.is_frozen() is True

    monkeypatch.setattr(updater, "__compiled__", False, raising=False)
    assert updater.is_frozen() is False


def test_frozen_exe_path_prefers_argv_exe(monkeypatch):
    """Nuitka 把 sys.executable 指到 python.exe，真正的 exe 在 sys.argv[0]。"""
    monkeypatch.setattr(updater.sys, "argv", [r"C:\app\IntegratedApp.exe"])
    monkeypatch.setattr(updater.sys, "executable", r"C:\app\python.exe")
    assert updater._frozen_exe_path().lower().endswith("integratedapp.exe")


def test_frozen_exe_path_falls_back_to_executable(monkeypatch):
    """argv 無法提供 .exe 時回退到 sys.executable。"""
    monkeypatch.setattr(updater.sys, "argv", [""])
    monkeypatch.setattr(updater.sys, "executable", r"C:\app\IntegratedApp.exe")
    assert updater._frozen_exe_path().lower().endswith("integratedapp.exe")


def test_apply_script_relaunch_uses_processstartinfo():
    """PS 5.1 的 Start-Process 沒有 -UseShellExecute 參數，重啟必須走 .NET ProcessStartInfo。"""
    script = updater._apply_script_content()
    assert "-UseShellExecute" not in script   # 防止誤用不存在的參數
    assert "System.Diagnostics.ProcessStartInfo" in script
    assert "$psi.UseShellExecute = $false" in script


# ------------------------------------------------------------------ #
# 多線程分段下載 (對本機 HTTP 伺服器測試，不連外網)
# ------------------------------------------------------------------ #
class _RangeHandler(http.server.BaseHTTPRequestHandler):
    """極簡測試伺服器：可選擇是否支援 HTTP Range。"""

    payload = b""
    supports_range = True

    def do_GET(self):
        data = type(self).payload
        rng = self.headers.get("Range")
        if rng and type(self).supports_range:
            m = re.match(r"bytes=(\d+)-(\d*)", rng)
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else len(data) - 1
            end = min(end, len(data) - 1)
            chunk = data[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Range",
                             "bytes {}-{}/{}".format(start, end, len(data)))
            self.send_header("Content-Length", str(len(chunk)))
            self.end_headers()
            self.wfile.write(chunk)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # 靜音
        pass


def _serve(payload, supports_range=True):
    handler = type("_H", (_RangeHandler,),
                   {"payload": payload, "supports_range": supports_range})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:{}/file.bin".format(httpd.server_address[1])
    return httpd, url


def test_probe_download_reports_total_and_range():
    data = os.urandom(4096)
    httpd, url = _serve(data)
    try:
        _final, total, supports = updater._probe_download(url)
        assert supports is True
        assert total == len(data)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_download_file_multipart(tmp_path):
    data = os.urandom(5 * 1024 * 1024)   # 大於 MIN_MULTIPART_SIZE，會走分段
    httpd, url = _serve(data)
    try:
        dest = tmp_path / "out.bin"
        events = []
        updater.download_file(url, str(dest), progress_cb=events.append, threads=4)
        assert dest.read_bytes() == data
        assert events, "應至少回報一次進度"
        assert events[-1]["downloaded"] == len(data)
        assert events[-1]["total"] == len(data)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_download_file_falls_back_to_single_when_no_range(tmp_path):
    data = os.urandom(5 * 1024 * 1024)
    httpd, url = _serve(data, supports_range=False)
    try:
        dest = tmp_path / "out.bin"
        updater.download_file(url, str(dest), threads=4)
        assert dest.read_bytes() == data
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_download_file_cancel_raises(tmp_path):
    data = os.urandom(5 * 1024 * 1024)
    httpd, url = _serve(data)
    try:
        cancel = threading.Event()
        cancel.set()
        with pytest.raises(updater.UpdateCancelled):
            updater.download_file(url, str(tmp_path / "out.bin"), cancel_event=cancel)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_cleanup_stale_downloads_removes_leftovers(monkeypatch, tmp_path):
    stale = tmp_path / "netredir_update_abc.zip"
    stale.write_bytes(b"partial")
    monkeypatch.setattr(updater.tempfile, "gettempdir", lambda: str(tmp_path))
    updater._cleanup_stale_downloads()
    assert not stale.exists()


class _StallingRangeHandler(http.server.BaseHTTPRequestHandler):
    """送出 headers 與少量 body 後就停住，模擬 socket 永不返回的卡死連線。"""

    total = 2 * 1024 * 1024

    def do_GET(self):
        total = type(self).total
        rng = self.headers.get("Range")
        m = re.match(r"bytes=(\d+)-(\d*)", rng) if rng else None
        if m:
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else total - 1
            end = min(end, total - 1)
        else:
            start, end = 0, total - 1
        chunk_len = end - start + 1
        self.send_response(206 if m else 200)
        if m:
            self.send_header("Content-Range",
                             "bytes {}-{}/{}".format(start, end, total))
        self.send_header("Content-Length", str(chunk_len))
        self.end_headers()
        try:
            self.wfile.write(b"x" * min(4096, chunk_len))
            self.wfile.flush()
        except OSError:
            return
        time.sleep(30)     # 卡住：不再送資料，也不關閉連線

    def log_message(self, *args):  # 靜音
        pass


def test_download_file_aborts_on_stalled_connection(monkeypatch, tmp_path):
    """連線送出少量資料後停滯時，watchdog 必須關閉連線中止，而非無限卡住。"""
    monkeypatch.setattr(updater, "NO_PROGRESS_TIMEOUT", 1)
    monkeypatch.setattr(updater, "_TIMEOUT_READ", 2)
    monkeypatch.setattr(updater, "STOP_GRACE", 3)
    monkeypatch.setattr(updater, "MIN_MULTIPART_SIZE", 1)
    monkeypatch.setattr(updater, "MAX_BLOCK_RETRIES", 1)

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _StallingRangeHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:{}/stall.bin".format(httpd.server_address[1])
    started = time.monotonic()
    try:
        with pytest.raises(Exception):
            updater.download_file(url, str(tmp_path / "out.bin"),
                                  threads=2, use_proxy=False)
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert time.monotonic() - started < 30, "停滯時應迅速中止，不應卡住"


# ------------------------------------------------------------------ #
# 選路探針重用：下載階段不該為了 final_url / total 再付一次 TTFB
# ------------------------------------------------------------------ #
def test_total_from_range_headers():
    total = updater._total_from_range_headers
    assert total({"content-range": "bytes 0-99/5000"}, 206) == 5000
    # 206 但長度未知 → 退回 content-length；都沒有則 0
    assert total({"content-range": "bytes 0-99/*"}, 206) == 0
    assert total({"content-length": "1234"}, 200) == 1234
    # 206 卻沒有 content-range 時退回 content-length，不可直接當成未知
    assert total({"content-length": "777"}, 206) == 777


class _ThrottledHandler(_RangeHandler):
    """分塊送出、塊間睡一下，讓探針的量測視窗長度可預期。

    迴環線路快到視窗幾乎為 0，會被 PROXY_PROBE_MIN_SECONDS 判成樣本不足；
    要驗證「有速度」就必須讓傳輸真的花掉一些時間。
    """

    delay = 0.03
    step = 256 * 1024

    def do_GET(self):
        data = type(self).payload
        rng = self.headers.get("Range")
        if rng and type(self).supports_range:
            m = re.match(r"bytes=(\d+)-(\d*)", rng)
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else len(data) - 1
            end = min(end, len(data) - 1)
            body = data[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Range",
                             "bytes {}-{}/{}".format(start, end, len(data)))
        else:
            body = data
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        for i in range(0, len(body), type(self).step):
            self.wfile.write(body[i:i + type(self).step])
            self.wfile.flush()
            time.sleep(type(self).delay)

    def log_message(self, *args):  # 靜音
        pass


def _serve_throttled(payload, supports_range=True, delay=0.03):
    handler = type("_H", (_ThrottledHandler,),
                   {"payload": payload, "supports_range": supports_range,
                    "delay": delay})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:{}/file.bin".format(httpd.server_address[1])
    return httpd, url


def test_measure_path_detailed_reports_final_url_and_total():
    """選路探針要順便帶回 final_url / total / supports_range 供下載階段重用。"""
    data = os.urandom(4 * 1024 * 1024)      # 16 塊 x 0.03s ≈ 0.5s 視窗
    httpd, url = _serve_throttled(data)
    try:
        speed, info = updater._measure_path_detailed(url, None)
        assert speed is not None, info
        assert speed > 0
        assert info["final_url"] == url
        assert info["total"] == len(data)
        assert info["supports_range"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_measure_path_detailed_no_range_reports_full_total():
    """伺服器不支援 Range 時，total 要退回 content-length 且標記不支援分段。"""
    data = os.urandom(4 * 1024 * 1024)
    httpd, url = _serve_throttled(data, supports_range=False)
    try:
        speed, info = updater._measure_path_detailed(url, None)
        assert speed is not None, info
        assert info["supports_range"] is False
        assert info["total"] == len(data)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_download_over_path_reuses_probe_info(tmp_path, monkeypatch):
    """帶了 probe_info 就不該再探一次 —— 那一次是 1.7~2.1 秒的完整 TTFB。"""
    data = os.urandom(5 * 1024 * 1024)
    httpd, url = _serve(data)
    called = []

    def boom(*a, **k):
        called.append(1)
        return (url, len(data), True)

    monkeypatch.setattr(updater, "_probe_download", boom)
    try:
        dest = tmp_path / "out.bin"
        updater._download_over_path(
            url, str(dest), None, 4, None, None,
            probe_info={"final_url": url, "total": len(data),
                        "supports_range": True})
        assert dest.read_bytes() == data
        assert called == [], "已提供 probe_info 時不應再呼叫 _probe_download"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_download_over_path_probes_when_info_missing(tmp_path, monkeypatch):
    """沒有 probe_info 時要退回自行探測，行為與舊版完全相同。"""
    data = os.urandom(5 * 1024 * 1024)
    httpd, url = _serve(data)
    real = updater._probe_download
    called = []

    def counting(*a, **k):
        called.append(1)
        return real(*a, **k)

    monkeypatch.setattr(updater, "_probe_download", counting)
    try:
        dest = tmp_path / "out.bin"
        updater._download_over_path(url, str(dest), None, 4, None, None)
        assert dest.read_bytes() == data
        assert called, "未提供 probe_info 時必須自行探測"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_download_over_path_probes_when_info_incomplete(tmp_path, monkeypatch):
    """probe_info 只給了 final_url、沒有 total 時，仍必須自行探測補齊。"""
    data = os.urandom(5 * 1024 * 1024)
    httpd, url = _serve(data)
    real = updater._probe_download
    called = []

    def counting(*a, **k):
        called.append(1)
        return real(*a, **k)

    monkeypatch.setattr(updater, "_probe_download", counting)
    try:
        dest = tmp_path / "out.bin"
        updater._download_over_path(
            url, str(dest), None, 4, None, None,
            probe_info={"final_url": url, "total": 0, "supports_range": True})
        assert dest.read_bytes() == data
        assert called, "資訊不全時必須自行探測"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_rank_download_paths_returns_probe_info(monkeypatch):
    """_rank_download_paths 的每個候選都要附帶自己的探針 info（4 元組）。"""
    info = {"final_url": "http://x/f.bin", "total": 123,
            "supports_range": True}
    monkeypatch.setattr(
        updater, "load_proxy_urls",
        lambda *a, **k: [{"name": "P", "url": "socks5h://1.2.3.4:1"}])
    monkeypatch.setattr(updater, "_measure_path_detailed",
                        lambda url, proxy_url, **k: (1000.0, dict(info)))

    ranked = updater._rank_download_paths("http://x/f.bin", use_proxy=True)
    assert len(ranked) == 2, ranked          # 代理 + 保底直連
    for _url, _speed, _label, got in ranked:
        assert got.get("final_url") == "http://x/f.bin"
        assert got.get("total") == 123


# --------------------------------------------------------------------------- #
# 伺服器「宣告支援 Range，實際回 416」
#
# 實測 http.speed.hinet.net 就是這種：標頭帶 Accept-Ranges: bytes，但任何
# Range 請求（連 bytes=0-0）都回 416。舊版引擎在這裡 0.02 秒就失敗 ——
# _probe_download 對 416 直接拋例外，於是 _download_over_path 根本走不到它
# 自己的單線備援；而 curl 抓同一個 URL 完全正常（40 MB / 3.77 秒 / 87 Mbps）。
#
# 既有的 test_download_file_falls_back_to_single_when_no_range 只涵蓋「忽略
# Range、回整份 200」，蓋不到「明確拒收」這條。
# --------------------------------------------------------------------------- #
class _RangeRejectingHandler(_RangeHandler):
    """任何帶 Range 的請求都回 416；不帶 Range 則正常回 200 全檔。"""

    def do_GET(self):
        if self.headers.get("Range"):
            body = b"416 Requested Range Not Satisfiable"
            self.send_response(416)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, *args):  # 靜音
        pass


def _serve_rejecting_range(payload):
    handler = type("_H", (_RangeRejectingHandler,), {"payload": payload})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:{}/file.bin".format(httpd.server_address[1])
    return httpd, url


class _ThrottledRangeRejectingHandler(_ThrottledHandler):
    """拒收 Range（416），其餘同 _ThrottledHandler（分塊送出 + 塊間睡）。

    量測視窗要驗「真的量到速度」就必須讓傳輸花掉時間：迴環線路上
    ``time.monotonic()`` 的差會是 0.0，走完整樣本分支時會被判「無法計時」。
    """

    def do_GET(self):
        if self.headers.get("Range"):
            body = b"416 Requested Range Not Satisfiable"
            self.send_response(416)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def _serve_throttled_rejecting_range(payload, delay=0.03):
    handler = type("_H", (_ThrottledRangeRejectingHandler,),
                   {"payload": payload, "delay": delay})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:{}/file.bin".format(httpd.server_address[1])
    return httpd, url


def test_range_rejected_classification():
    assert updater._range_rejected(416)
    assert updater._range_rejected(501)
    assert updater._range_rejected(400)
    # 「忽略 Range、回整份 200」不算拒絕 —— 那是另一條路徑（supports_range=False）
    assert not updater._range_rejected(200)
    assert not updater._range_rejected(206)
    assert not updater._range_rejected(404)


def test_probe_download_falls_back_when_range_rejected():
    data = os.urandom(4096)
    httpd, url = _serve_rejecting_range(data)
    try:
        _final, total, supports = updater._probe_download(url)
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert total == len(data)      # 拿掉 Range 之後仍量得到長度
    assert supports is False       # 但明確不可分段


def test_measure_path_detailed_falls_back_when_range_rejected():
    data = os.urandom(512 * 1024)
    httpd, url = _serve_throttled_rejecting_range(data)
    try:
        speed, info = updater._measure_path_detailed(url, None)
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert info["error"] is None, info
    assert info["supports_range"] is False
    assert info["total"] == len(data)
    assert speed is not None and speed > 0


def test_download_file_survives_range_rejecting_server(tmp_path):
    """端到端：這種伺服器舊版會直接失敗，修好後必須抓到完整內容。"""
    data = os.urandom(512 * 1024)
    httpd, url = _serve_rejecting_range(data)
    dest = tmp_path / "out.bin"
    try:
        updater.download_file(url, str(dest), threads=4, use_proxy=False)
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert dest.read_bytes() == data


# ------------------------------------------------------------------ #
# 自適應連線數
# ------------------------------------------------------------------ #
class _RecordingThrottledHandler(_ThrottledHandler):
    """同 _ThrottledHandler，但把每個請求的 Range 起點記下來。

    用來證明聚合量測真的是「每條連線從不同偏移起讀」，而不是大家一起讀
    同一段（那會把同一批位元組算 n 次，憑空生出 n 倍吞吐）。
    """

    starts = None
    lock = None

    def do_GET(self):
        rng = self.headers.get("Range")
        if rng:
            m = re.match(r"bytes=(\d+)-", rng)
            if m:
                with type(self).lock:
                    type(self).starts.append(int(m.group(1)))
        super().do_GET()

    def log_message(self, *args):  # 靜音
        pass


def _serve_recording_throttled(payload, delay=0.05):
    starts = []
    handler = type("_H", (_RecordingThrottledHandler,),
                   {"payload": payload, "delay": delay,
                    "starts": starts, "lock": threading.Lock()})
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:{}/file.bin".format(httpd.server_address[1])
    return httpd, url, starts


def _fake_multipart(monkeypatch, calls):
    """把 _download_multipart 換成只記錄 threads 的假函式。"""
    def fake(final_url, dest, total, threads, progress_cb, cancel_event,
             proxy_url=None):
        calls.append(threads)
        with open(dest, "wb") as f:
            f.write(b"\0" * total)
    monkeypatch.setattr(updater, "_download_multipart", fake)


def _probe_info(url, total, speed=1.0e6, ttfb=0.5):
    return {"final_url": url, "total": total, "supports_range": True,
            "speed": speed, "ttfb": ttfb, "bytes": 1024, "elapsed": 1.0,
            "error": None}


def test_config_flag_reads_boolean(tmp_path):
    cfg = tmp_path / "config.json"
    paths = [str(cfg)]
    cfg.write_text('{"adaptive_concurrency": true}', encoding="utf-8")
    assert updater._config_flag("adaptive_concurrency", False, paths) is True
    cfg.write_text('{"adaptive_concurrency": "on"}', encoding="utf-8")
    assert updater._config_flag("adaptive_concurrency", False, paths) is True
    cfg.write_text('{"adaptive_concurrency": false}', encoding="utf-8")
    assert updater._config_flag("adaptive_concurrency", True, paths) is False
    cfg.write_text("{ not json", encoding="utf-8")
    assert updater._config_flag("adaptive_concurrency", False, paths) is False
    missing = [str(tmp_path / "none.json")]
    assert updater._config_flag("x", True, missing) is True


def test_adaptive_off_by_default_keeps_threads(tmp_path, monkeypatch):
    """預設關閉：threads 照傳，連試探都不做 —— 行為與舊版完全相同。"""
    monkeypatch.setattr(updater, "ADAPTIVE_CONCURRENCY", False)
    monkeypatch.setattr(updater, "_config_flag", lambda *a, **k: False)
    monkeypatch.setattr(updater, "_measure_aggregate_throughput",
                        lambda *a, **k: pytest.fail("關閉時不該試探"))
    calls = []
    _fake_multipart(monkeypatch, calls)
    pi = _probe_info("http://x/f.bin", 64 * 1024 * 1024)
    updater._download_over_path("http://x/f.bin", str(tmp_path / "o.bin"),
                                None, 5, None, None, probe_info=pi)
    assert calls == [5]


def test_adaptive_uses_single_thread_when_no_gain(tmp_path, monkeypatch):
    """試探成功但吞吐沒明顯變好 → 退回單連線（這是實測那條路的結論）。"""
    monkeypatch.setattr(updater, "ADAPTIVE_CONCURRENCY", True)
    monkeypatch.setattr(updater, "_measure_aggregate_throughput",
                        lambda *a, **k: (1.02e6, 0.5, None))
    calls = []
    _fake_multipart(monkeypatch, calls)
    pi = _probe_info("http://x/f.bin", 64 * 1024 * 1024, speed=1.0e6)
    logs = []
    updater._download_over_path("http://x/f.bin", str(tmp_path / "o.bin"),
                                None, 8, None, None, probe_info=pi,
                                log_cb=logs.append)
    assert calls == [1]
    assert any("退回單連線" in m for m in logs), logs


def test_adaptive_adopts_more_threads_when_gain_is_high(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "ADAPTIVE_CONCURRENCY", True)
    monkeypatch.setattr(updater, "_measure_aggregate_throughput",
                        lambda *a, **k: (2.0e6, 0.5, None))
    calls = []
    _fake_multipart(monkeypatch, calls)
    pi = _probe_info("http://x/f.bin", 64 * 1024 * 1024, speed=1.0e6)
    updater._download_over_path("http://x/f.bin", str(tmp_path / "o.bin"),
                                None, 8, None, None, probe_info=pi)
    assert calls == [updater.ADAPTIVE_PROBE_THREADS]


def test_adaptive_threads_backs_off_when_latency_rises(monkeypatch):
    """吞吐變好但延遲也漲 → 過度連線，不採用（Vegas 式煞車）。"""
    total = 64 * 1024 * 1024
    url = "http://x/f.bin"
    info = _probe_info(url, total, speed=1.0e6, ttfb=0.5)
    lat = updater.ADAPTIVE_LATENCY_TOLERANCE * 1.2
    monkeypatch.setattr(updater, "_measure_aggregate_throughput",
                        lambda *a, **k: (2.0e6, info["ttfb"] * lat, None))
    got, why = updater._adaptive_threads(url, total, None, 8, info)
    assert 2.0e6 / info["speed"] >= updater.ADAPTIVE_GAIN
    assert lat > updater.ADAPTIVE_LATENCY_TOLERANCE
    assert got == 1, why


def test_adaptive_threads_skips_probe_for_small_file(monkeypatch):
    monkeypatch.setattr(updater, "_measure_aggregate_throughput",
                        lambda *a, **k: pytest.fail("小檔案不該試探"))
    small = updater.ADAPTIVE_MIN_BYTES - 1
    got, why = updater._adaptive_threads(
        "http://x/f.bin", small, None, 8,
        _probe_info("http://x/f.bin", small))
    assert got == 8, why


def test_adaptive_threads_skips_probe_when_estimate_is_short(monkeypatch):
    """估計下載時間比試探成本還短 → 不試探（尊重呼叫端的設定值）。"""
    monkeypatch.setattr(updater, "_measure_aggregate_throughput",
                        lambda *a, **k: pytest.fail("估計太短不該試探"))
    total = 64 * 1024 * 1024
    url = "http://x/f.bin"
    info = _probe_info(url, total, speed=100e6, ttfb=0.5)
    got, why = updater._adaptive_threads(url, total, None, 8, info)
    assert got == 8, why


def test_adaptive_threads_falls_back_to_base_when_probe_fails(monkeypatch):
    monkeypatch.setattr(updater, "_measure_aggregate_throughput",
                        lambda *a, **k: (None, None, "boom"))
    total = 64 * 1024 * 1024
    got, why = updater._adaptive_threads(
        "http://x/f.bin", total, None, 8, _probe_info("http://x/f.bin", total))
    assert got == 8, why
    assert "boom" in why


def test_adaptive_threads_falls_back_without_baseline():
    total = 64 * 1024 * 1024
    got, why = updater._adaptive_threads("http://x/f.bin", total, None, 8, {})
    assert got == 8, why


def test_measure_aggregate_throughput_guards():
    agg = updater._measure_aggregate_throughput
    assert agg("http://x/f", 0, None, 4)[0] is None
    tiny = 4 * 1024 * 1024
    bw, _ttfb, why = agg("http://x/f", tiny, None, 64)
    assert bw is None and "太小" in why


def test_measure_aggregate_throughput_uses_distinct_offsets():
    """聚合量測必須讓每條連線讀不同區間，否則會憑空生出 n 倍吞吐。"""
    total = 6 * 1024 * 1024
    httpd, url, starts = _serve_recording_throttled(bytes(total))
    try:
        bw, ttfb, why = updater._measure_aggregate_throughput(
            url, total, None, 3, seconds=0.3, max_bytes=1024 * 1024)
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert why is None, why
    assert bw is not None and bw > 0
    assert ttfb is not None and ttfb >= 0
    assert len(starts) == 3, starts
    assert len(set(starts)) == 3, starts
    assert min(starts) == 0 and max(starts) == 2 * (total // 3), starts
