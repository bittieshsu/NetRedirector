"""
process_utils.py — 列舉系統執行中的進程 (Windows Toolhelp32 API)。

直接以 ctypes 呼叫 kernel32，不引入 psutil 等額外相依 (打包體積/授權)，
且在非 Windows 平台回傳空清單，讓 GUI 能優雅降級。
"""

import ctypes
import sys

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260


class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


def list_processes():
    """回傳 [(進程名稱, PID), ...]，依名稱排序 (不分大小寫)。

    同名進程只保留一個 (最小 PID)，避免 chrome.exe 這類多程序應用洗版。
    非 Windows 或 API 失敗時回傳空清單 (呼叫端顯示空表格即可)。
    """
    if not sys.platform.startswith("win"):
        return []

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Process32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32)]
    kernel32.Process32First.restype = ctypes.c_int
    kernel32.Process32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32)]
    kernel32.Process32Next.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    invalid_handle = ctypes.c_void_p(-1).value
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == invalid_handle:
        return []

    unique = {}
    try:
        entry = _PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32)
        has_entry = kernel32.Process32First(snapshot, ctypes.byref(entry))
        while has_entry:
            name = entry.szExeFile.decode("utf-8", errors="ignore").strip()
            pid = int(entry.th32ProcessID)
            if name and pid:
                key = name.lower()
                previous = unique.get(key)
                if previous is None or pid < previous[1]:
                    unique[key] = (name, pid)
            has_entry = kernel32.Process32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    return sorted(unique.values(), key=lambda item: item[0].lower())


def list_process_names():
    """只回傳去重後的進程名稱 (依名稱排序)。"""
    return [name for name, _pid in list_processes()]
