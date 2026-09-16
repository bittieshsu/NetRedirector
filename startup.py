# -*- coding: utf-8 -*-
"""Windows 開機自動啟動（登入時以「最高權限」執行）。

為什麼不用 HKCU\\...\\Run 機碼？
    NetRedirector 必須以管理員權限執行才能載入 WinDivert 驅動。Run 機碼
    只能以一般（未提升）權限啟動程式，登入後程式會因 IsUserAnAdmin()
    失敗而直接結束 —— 直接照搬其他專案（例如 MultiSocksDownloader）
    的 Run 機碼做法時，這是最容易踩到的坑。
    因此改用「工作排程器」建立一個「登入時觸發、以最高權限執行」的工作，
    登入後不需 UAC 提示即可自動啟動。

Nuitka 打包的兩個坑（處理方式沿用 MultiSocksDownloader）：
    1. Nuitka 不設 sys.frozen，而是注入 __compiled__ 全域變數，只檢查
       sys.frozen 會把打包版誤判為原始碼模式、寫出指向 python.exe 的錯誤命令。
    2. Nuitka standalone 的 sys.executable 指向 dist 內建的 python.exe，
       真正的程式 exe 要用 sys.argv[0] 才拿得到。

第三個坑：工作排程器啟動程式時的工作目錄是 System32，而本程式使用的
    NetRedirector.dll / config.json / locale 都是相對路徑。enable() 會
    一併設定工作的 WorkingDirectory，程式端另有
    ensure_working_directory() 作為雙重保險。
"""

import base64
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

# 工作排程器中的工作名稱：固定不變，停用時才能精準移除自己建立的工作。
TASK_NAME = "NetRedirector GameProxyHub"

# 背景執行子程序時避免閃出主控台視窗。
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def is_supported():
    """本模組僅支援 Windows；其他平台一律視為不支援 (no-op)。"""
    return sys.platform == "win32"


def _is_frozen():
    """是否為打包後的獨立執行檔（涵蓋 PyInstaller / Nuitka）。

    Nuitka 預設「不會」設定 sys.frozen，而是注入 __compiled__ 全域變數，
    因此不能只檢查 sys.frozen。
    """
    if getattr(sys, "frozen", False):          # PyInstaller / cx_Freeze
        return True
    if hasattr(sys, "_MEIPASS"):               # PyInstaller onefile
        return True
    if globals().get("__compiled__", False):   # Nuitka 注入的模組全域變數
        return True
    return False


def _frozen_exe_path():
    """取得真正執行中的程式 exe 路徑。

    Nuitka standalone 會把 sys.executable 設成 dist 內建的 python.exe
    （甚至是不存在的路徑），真正的程式 exe 要用 sys.argv[0] 才拿得到。
    """
    argv0 = sys.argv[0] if sys.argv else ""
    p = os.path.abspath(argv0) if argv0 else ""
    if p and p.lower().endswith(".exe"):
        return p
    exe = sys.executable or ""
    if exe.lower().endswith(".exe"):
        return os.path.abspath(exe)
    return p


def app_base_dir():
    """程式所在資料夾（打包後為 .dist 目錄，原始碼模式為專案根目錄）。"""
    if _is_frozen():
        exe = _frozen_exe_path()
        if exe:
            return os.path.dirname(exe)
    return os.path.dirname(os.path.abspath(__file__))


def _entry_script():
    """原始碼模式的入口腳本路徑。"""
    return os.path.join(app_base_dir(), "IntegratedApp.py")


def executable_and_args():
    """回傳啟動工作需要的 (執行檔, 參數, 工作目錄)。

    打包後直接執行真正的程式 exe（不帶參數）；原始碼執行時改用無視窗的
    pythonw.exe 執行入口腳本，避免登入時閃出命令列視窗。
    """
    if _is_frozen():
        exe = _frozen_exe_path()
        return exe, "", os.path.dirname(exe)

    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    pythonw = os.path.join(exe_dir, "pythonw.exe")
    exe = pythonw if os.path.isfile(pythonw) else sys.executable
    script = _entry_script()
    return exe, '"{}"'.format(script), os.path.dirname(script)


def executable_command():
    """回傳開機啟動使用的完整命令列（供顯示與 schtasks 後備路徑使用）。"""
    exe, args, _ = executable_and_args()
    cmd = '"{}"'.format(exe)
    return cmd + (" " + args if args else "")


def _command_target(value):
    """從啟動命令取出（第一個）執行檔路徑；取不到時回傳 None。

    - 有引號：取第一組引號內的內容（schtasks 建立的 Command 會帶引號）。
    - 無引號：先看整串是否為存在的檔案（PowerShell 建立的路徑含空白時
      不會加引號），否則以第一個空白切開。
    """
    value = (value or "").strip()
    if not value:
        return None
    if value.startswith('"'):
        end = value.find('"', 1)
        return value[1:end] if end > 1 else None
    if os.path.isfile(value):
        return value
    return value.split(" ", 1)[0]


def _run(args):
    """執行外部命令；找不到執行檔等 OSError 時回傳 None。"""
    try:
        return subprocess.run(
            args, capture_output=True, creationflags=_CREATE_NO_WINDOW)
    except OSError:
        return None


def _query_task_xml():
    """查詢本程式的工作定義 XML；不存在或查詢失敗時回傳 None。"""
    if not is_supported():
        return None
    proc = _run(["schtasks", "/query", "/tn", TASK_NAME, "/xml"])
    if proc is None or proc.returncode != 0:
        return None
    raw = proc.stdout or b""
    # schtasks /xml 的宣告雖寫 UTF-16，實際輸出多為無 BOM 的 UTF-8；
    # 依 BOM 判斷可避免解碼錯誤導致誤判為「未啟用」。
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def _extract_command(xml):
    """從工作 XML 取出 <Actions><Exec><Command> 的執行檔路徑。"""
    if not xml:
        return None
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    el = root.find(".//{0}Actions/{0}Exec/{0}Command".format(_TASK_NS))
    return el.text if el is not None else None


def is_enabled():
    """判斷目前是否已設定本程式登入自動啟動。

    除了工作存在，也確認命令指向的執行檔仍存在；若指向失效路徑
    （例如換版本後殘留的舊命令），視為未啟用，讓 enable() 有機會重寫。
    """
    if not is_supported():
        return False
    target = _command_target(_extract_command(_query_task_xml()))
    return bool(target) and os.path.isfile(target)


def _ps_quote(value):
    """把字串包成 PowerShell 單引號字面量（單引號以兩個表示）。"""
    return "'" + str(value).replace("'", "''") + "'"


def _enable_via_powershell(exe, args, workdir):
    """以 Register-ScheduledTask 建立工作（可完整控制電源/時限設定）。"""
    action = "$a=New-ScheduledTaskAction -Execute {}".format(_ps_quote(exe))
    if args:
        action += " -Argument {}".format(_ps_quote(args))
    if workdir:
        action += " -WorkingDirectory {}".format(_ps_quote(workdir))

    script = "; ".join([
        "$ProgressPreference='SilentlyContinue'",
        "$ErrorActionPreference='Stop'",
        action,
        "$t=New-ScheduledTaskTrigger -AtLogOn",
        # 允許電池供電時啟動、不因切換到電池而停止，並取消執行時間上限
        # （長駐的代理程式若被排程器在 72 小時後終止會直接斷線）。
        "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries"
        " -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)"
        " -MultipleInstances IgnoreNew",
        "Register-ScheduledTask -TaskName {} -Action $a -Trigger $t"
        " -Settings $s -RunLevel Highest -Force | Out-Null".format(
            _ps_quote(TASK_NAME)),
    ])

    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    proc = _run([
        "powershell", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded,
    ])
    return proc is not None and proc.returncode == 0


def _enable_via_schtasks(exe, args, workdir):
    """後備路徑：以 schtasks 建立工作（無法調整電源設定，但相容性最好）。"""
    cmd = '"{}"'.format(exe) + (" " + args if args else "")
    proc = _run([
        "schtasks", "/create", "/tn", TASK_NAME, "/tr", cmd,
        "/sc", "onlogon", "/rl", "highest", "/f",
    ])
    return proc is not None and proc.returncode == 0


def enable():
    """設定本程式登入自動啟動。回傳 True 表示成功。

    先用 PowerShell 的 Register-ScheduledTask（可設定允許電池啟動、
    無執行時間上限），失敗時退回 schtasks 命令列。
    """
    if not is_supported():
        return False
    exe, args, workdir = executable_and_args()
    if not exe or not os.path.isfile(exe):
        return False
    if _enable_via_powershell(exe, args, workdir):
        return True
    return _enable_via_schtasks(exe, args, workdir)


def disable():
    """移除本程式的登入自動啟動工作；未設定過時為無操作。"""
    if not is_supported():
        return
    _run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"])


def ensure_working_directory():
    """把工作目錄切到程式所在資料夾。

    由工作排程器啟動時的工作目錄是 System32，若不切換，程式使用的
    NetRedirector.dll / config.json / locale 等相對路徑會全部找不到。
    """
    base = app_base_dir()
    if not base or not os.path.isdir(base):
        return
    try:
        if os.path.abspath(os.getcwd()) != os.path.abspath(base):
            os.chdir(base)
    except OSError:
        pass
