# -*- coding: utf-8 -*-
"""secure_config 單元測試 — DPAPI 加密/解密往返與舊版相容"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secure_config as sc


def test_available_on_windows():
    assert sc.is_available() is True  # 本機為 Windows


def test_empty_password_roundtrip():
    assert sc.encrypt_password("") == ""
    assert sc.decrypt_password("") == ""


def test_encrypted_prefix():
    enc = sc.encrypt_password("hello")
    assert enc.startswith(sc.PREFIX)


def test_roundtrip_simple():
    pwd = "MyP@ssw0rd!"
    assert sc.decrypt_password(sc.encrypt_password(pwd)) == pwd


def test_roundtrip_unicode():
    pwd = "測試密碼!@#$%^&*()中文"
    assert sc.decrypt_password(sc.encrypt_password(pwd)) == pwd


def test_roundtrip_long():
    pwd = "x" * 255  # C 核心欄位上限
    assert sc.decrypt_password(sc.encrypt_password(pwd)) == pwd


def test_legacy_plaintext_compat():
    # 舊版 config.json 的明文密碼 (無 dpapi: 前綴) 原樣回傳
    assert sc.decrypt_password("oldplain") == "oldplain"


def test_encrypted_is_not_plaintext():
    # 加密結果不可包含明文
    enc = sc.encrypt_password("secret123")
    assert "secret123" not in enc
