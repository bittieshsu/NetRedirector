# -*- coding: utf-8 -*-
"""updater 純邏輯單元測試 — 版本比對 / SHA256 校驗 (不觸及網路)。"""

import hashlib
import http.server
import os
import re
import sys
import threading

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

