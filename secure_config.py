"""
secure_config.py — 敏感資料的安全儲存輔助模組

使用 Windows DPAPI (CryptProtectData / CryptUnprotectData) 加密代理密碼，
避免以明文寫入 config.json。

- 加密結果格式: "dpapi:<base64>"
- 舊版明文密碼 (無 dpapi: 前綴) 在讀取時自動相容，直接回傳原值
- DPAPI 與「目前 Windows 使用者帳戶 + 機器」綁定；設定檔被複製到其他
  使用者/機器時無法解密，此時回傳空字串並輸出警告（需重新輸入密碼）

注意：此處僅保護「靜態存放」的密碼；執行期間密碼仍以明文存在記憶體中
（原本就是如此），不在本模組處理範圍。
"""

import base64
import ctypes
import sys
from ctypes import wintypes

PREFIX = "dpapi:"

# --- Win32 DATA_BLOB ---

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _blob_from_bytes(data: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = DATA_BLOB()
    blob.cbData = len(data)
    blob.pbData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    return blob


def _bytes_from_blob(blob: DATA_BLOB) -> bytes:
    if blob.cbData == 0 or not blob.pbData:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


# --- 載入 crypt32 / kernel32 並定義原型 (支援 64-bit) ---

def _load_crypt32():
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32

        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptProtectData.restype = wintypes.BOOL

        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
        ]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL

        kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        kernel32.LocalFree.restype = wintypes.HLOCAL
        return crypt32, kernel32
    except Exception:
        return None, None


_crypt32, _kernel32 = _load_crypt32()
_available = _crypt32 is not None and _kernel32 is not None


def is_available() -> bool:
    """DPAPI 是否可用 (Windows 上通常恆為 True)。"""
    return _available


def encrypt_password(plain: str) -> str:
    """加密密碼供儲存。空字串原樣回傳；加密失敗時回退為明文並警告。"""
    if not plain:
        return ""
    if not _available:
        print("[secure_config] DPAPI 不可用，密碼將以明文儲存", file=sys.stderr)
        return plain
    try:
        in_blob = _blob_from_bytes(plain.encode("utf-8"))
        out_blob = DATA_BLOB()
        if not _crypt32.CryptProtectData(
            ctypes.byref(in_blob), None, None, None, None, 0,
            ctypes.byref(out_blob),
        ):
            print("[secure_config] CryptProtectData 失敗，密碼將以明文儲存", file=sys.stderr)
            return plain
        enc = base64.b64encode(_bytes_from_blob(out_blob)).decode("ascii")
        _kernel32.LocalFree(out_blob.pbData)
        return PREFIX + enc
    except Exception as e:
        print(f"[secure_config] 加密失敗 ({e})，密碼將以明文儲存", file=sys.stderr)
        return plain


def decrypt_password(stored: str) -> str:
    """解密先前儲存的密碼。非 dpapi: 前綴視為舊版明文直接回傳；
    解密失敗 (例如設定檔來自其他使用者/機器) 時回傳空字串並警告。"""
    if not stored:
        return ""
    if not stored.startswith(PREFIX):
        return stored  # 舊版明文，相容
    if not _available:
        print("[secure_config] DPAPI 不可用，無法解密密碼", file=sys.stderr)
        return ""
    try:
        raw = base64.b64decode(stored[len(PREFIX):])
        in_blob = _blob_from_bytes(raw)
        out_blob = DATA_BLOB()
        if not _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 0,
            ctypes.byref(out_blob),
        ):
            print("[secure_config] CryptUnprotectData 失敗 (設定檔來自其他使用者/機器?)，請重新輸入密碼", file=sys.stderr)
            return ""
        data = _bytes_from_blob(out_blob)
        _kernel32.LocalFree(out_blob.pbData)
        return data.decode("utf-8")
    except Exception as e:
        print(f"[secure_config] 解密失敗 ({e})，請重新輸入密碼", file=sys.stderr)
        return ""
