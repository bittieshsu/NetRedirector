# -*- coding: utf-8 -*-
"""config_store 單元測試 — 設定序列化 (DPAPI 加密) 與檔案 I/O"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config_store
import secure_config


def sample_state():
    proxies = [
        {"name": "P1", "type": "SOCKS5", "ip": "127.0.0.1", "port": 1080,
         "user": "u", "pass": "secret123", "latency": "-"},
        {"name": "P2", "type": "HTTP", "ip": "1.2.3.4", "port": 3128,
         "user": "", "pass": "", "latency": "5"},
    ]
    rules = [
        {"type": "Name", "target": "chrome.exe", "hosts": "*", "ports": "*",
         "proto": "BOTH", "action": "PROXY (轉發)", "action_key": 0, "proxy": "[Custom] P1"},
        {"type": "PID", "target": "1234", "hosts": "8.8.8.8", "ports": "443",
         "proto": "TCP", "action": "DIRECT (直連)", "action_key": 1, "proxy": "Direct"},
    ]
    return proxies, rules


def test_build_config_data_structure():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "1.1.1.1", {1080: ["A"]}, proxies, rules)
    assert data["lang"] == "zh_TW"
    assert data["ping_target"] == "1.1.1.1"
    assert data["hubs"] == {1080: ["A"]}
    assert len(data["proxies"]) == 2
    assert len(data["rules"]) == 2


def test_proxy_password_dpapi_encrypted():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", {}, proxies, rules)
    enc = data["proxies"][0]["pass"]
    assert enc.startswith(secure_config.PREFIX)
    assert "secret123" not in enc
    # 解密可還原
    assert secure_config.decrypt_password(enc) == "secret123"
    # 空密碼保持空字串
    assert data["proxies"][1]["pass"] == ""


def test_rules_preserve_ui_fields():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", {}, proxies, rules)
    r = data["rules"][0]
    assert r["proxy_text"] == "[Custom] P1"
    assert r["target"] == "chrome.exe"
    assert r["action_key"] == 0
    assert r["hosts"] == "*"


def test_dynamic_fields_removed():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", {}, proxies, rules)
    # latency / id 不得出現在序列化結果
    assert "latency" not in data["proxies"][0]
    assert "id" not in data["proxies"][0]


def test_save_and_load_roundtrip(tmp_path):
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "8.8.8.8", {}, proxies, rules)
    path = os.path.join(tmp_path, "config.json")
    assert config_store.save_config_file(path, data) is None
    loaded = config_store.load_config_file(path)
    assert loaded is not None
    assert loaded["proxies"][0]["name"] == "P1"
    assert secure_config.decrypt_password(loaded["proxies"][0]["pass"]) == "secret123"
    assert loaded["rules"][1]["type"] == "PID"
    assert loaded["ping_target"] == "8.8.8.8"


def test_load_missing_file_returns_none(tmp_path):
    assert config_store.load_config_file(os.path.join(tmp_path, "nope.json")) is None


def test_load_corrupt_file_returns_none(tmp_path):
    path = os.path.join(tmp_path, "bad.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write("{not valid json")
    assert config_store.load_config_file(path) is None


def test_save_to_bad_path_returns_error():
    err = config_store.save_config_file("Z:/no/such/dir/config.json", {})
    assert err is not None
