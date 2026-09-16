# -*- coding: utf-8 -*-
"""startup 單元測試 — 開機自動啟動 (Windows 工作排程器)。

外部命令 (schtasks / powershell) 一律以 mock 取代，不實際更動系統排程。
"""
import base64
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import startup


TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions Context="Author">
    <Exec>
      <Command>{cmd}</Command>
      <WorkingDirectory>C:\\app</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _proc(args, rc=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(args, rc, stdout, stderr)


# --------------------------------------------------------------- frozen 偵測
def test_not_frozen_in_source_run():
    # 測試環境本身即原始碼執行，不應被判定為打包版
    assert startup._is_frozen() is False


def test_nuitka_compiled_marker_counts_as_frozen(monkeypatch):
    # Nuitka 不設 sys.frozen，只注入 __compiled__；須能正確辨識
    monkeypatch.setattr(startup, "__compiled__", True, raising=False)
    assert startup._is_frozen() is True


# --------------------------------------------------------------- 命令組合
def test_source_command_targets_entry_script(monkeypatch):
    monkeypatch.setattr(startup, "_is_frozen", lambda: False)
    exe, args, workdir = startup.executable_and_args()
    assert exe.lower().endswith(".exe")
    assert "IntegratedApp.py" in args
    assert "IntegratedApp.py" in startup.executable_command()
    assert "%1" not in startup.executable_command()  # 開機啟動不帶檔案參數
    assert workdir == os.path.dirname(startup._entry_script())


def test_frozen_command_points_at_real_exe(monkeypatch):
    # 打包版：sys.executable 會是 dist\python.exe，真正 exe 在 argv[0]，
    # 命令必須指向 argv[0]，且不得含 .py 腳本或 python.exe。
    monkeypatch.setattr(startup, "_is_frozen", lambda: True)
    monkeypatch.setattr(startup.sys, "argv", [r"D:\app\IntegratedApp.exe"])
    monkeypatch.setattr(startup.sys, "executable", r"D:\app\python.exe")
    exe, args, workdir = startup.executable_and_args()
    assert exe == r"D:\app\IntegratedApp.exe"
    assert args == ""
    assert workdir == r"D:\app"
    assert startup.executable_command() == r'"D:\app\IntegratedApp.exe"'


def test_command_target_variants(tmp_path):
    existing = tmp_path / "app.exe"
    existing.write_text("", encoding="utf-8")
    # 有引號：取第一組引號內容 (schtasks 建立的 Command 會帶引號)
    assert startup._command_target('"C:\\a b\\app.exe" "C:\\x.py"') == "C:\\a b\\app.exe"
    # 無引號且非現存檔案：以第一個空白切開
    assert startup._command_target("C:\\app.exe --flag") == "C:\\app.exe"
    # 無引號但整串是現存檔案 (PowerShell 建立、路徑含空白時不加引號)
    assert startup._command_target(str(existing)) == str(existing)
    assert startup._command_target("") is None
    assert startup._command_target(None) is None


def test_extract_command_handles_bad_xml():
    assert startup._extract_command("") is None
    assert startup._extract_command("<not-xml") is None


# --------------------------------------------------------------- 狀態判斷
def test_is_enabled_true_when_task_target_exists(monkeypatch, tmp_path):
    exe = tmp_path / "IntegratedApp.exe"
    exe.write_text("", encoding="utf-8")
    xml = TASK_XML.format(cmd=str(exe)).encode("utf-8")
    monkeypatch.setattr(startup, "_run", lambda a: _proc(a, 0, xml))
    assert startup.is_enabled() is True


def test_is_enabled_false_when_target_missing(monkeypatch):
    # 工作存在但指向失效路徑 (舊版殘留) → 視為未啟用，讓 enable() 有機會重寫
    xml = TASK_XML.format(cmd=r"C:\ghost\app.exe").encode("utf-8")
    monkeypatch.setattr(startup, "_run", lambda a: _proc(a, 0, xml))
    assert startup.is_enabled() is False


def test_is_enabled_false_when_task_absent(monkeypatch):
    monkeypatch.setattr(startup, "_run", lambda a: _proc(a, 1))
    assert startup.is_enabled() is False


# --------------------------------------------------------------- 啟用/停用
def test_enable_registers_logon_task_with_highest_privileges(monkeypatch, tmp_path):
    exe = tmp_path / "IntegratedApp.exe"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(startup, "_is_frozen", lambda: True)
    monkeypatch.setattr(startup.sys, "argv", [str(exe)])
    calls = []

    def fake_run(args):
        calls.append(args)
        return _proc(args, 0)

    monkeypatch.setattr(startup, "_run", fake_run)
    assert startup.enable() is True
    assert len(calls) == 1
    assert calls[0][0].lower().startswith("powershell")
    encoded = calls[0][calls[0].index("-EncodedCommand") + 1]
    script = base64.b64decode(encoded).decode("utf-16-le")
    assert "Register-ScheduledTask" in script
    assert "-AtLogOn" in script
    assert "-RunLevel Highest" in script
    # 允許電池供電啟動、且不設執行時間上限 (長駐代理程式不可被排程器終止)
    assert "-AllowStartIfOnBatteries" in script
    assert "-DontStopIfGoingOnBatteries" in script
    assert "ExecutionTimeLimit" in script


def test_enable_falls_back_to_schtasks(monkeypatch, tmp_path):
    exe = tmp_path / "IntegratedApp.exe"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(startup, "_is_frozen", lambda: True)
    monkeypatch.setattr(startup.sys, "argv", [str(exe)])
    calls = []

    def fake_run(args):
        calls.append(args)
        # 第一次 (PowerShell) 失敗，第二次 (schtasks) 成功
        return _proc(args, 1 if args[0].lower().startswith("powershell") else 0)

    monkeypatch.setattr(startup, "_run", fake_run)
    assert startup.enable() is True
    assert len(calls) == 2
    assert calls[1][0].lower() == "schtasks"
    assert "/sc" in calls[1] and "onlogon" in calls[1]


def test_enable_returns_false_when_exe_missing(monkeypatch):
    def fail_run(args):
        raise AssertionError("不應呼叫外部命令")

    monkeypatch.setattr(startup, "_is_frozen", lambda: True)
    monkeypatch.setattr(startup.sys, "argv", [r"D:\ghost\IntegratedApp.exe"])
    monkeypatch.setattr(startup, "_run", fail_run)
    assert startup.enable() is False


def test_disable_deletes_task(monkeypatch):
    calls = []
    monkeypatch.setattr(startup, "_run", lambda a: calls.append(a) or _proc(a, 0))
    startup.disable()
    assert calls == [["schtasks", "/delete", "/tn", startup.TASK_NAME, "/f"]]


def test_non_windows_is_noop(monkeypatch):
    monkeypatch.setattr(startup.sys, "platform", "linux")
    assert startup.is_supported() is False
    assert startup.is_enabled() is False
    assert startup.enable() is False
    startup.disable()  # 不應拋出例外


# --------------------------------------------------------------- 工作目錄
def test_ensure_working_directory_changes_cwd(monkeypatch, tmp_path):
    # 由工作排程器啟動時工作目錄是 System32，必須切回程式資料夾，
    # 否則 DLL / config.json / locale 等相對路徑會找不到。
    monkeypatch.setattr(startup, "app_base_dir", lambda: str(tmp_path))
    old = os.getcwd()
    try:
        startup.ensure_working_directory()
        assert os.path.abspath(os.getcwd()) == os.path.abspath(str(tmp_path))
    finally:
        os.chdir(old)
