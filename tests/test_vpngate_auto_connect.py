# -*- coding: utf-8 -*-
"""VPN Gate 自動連線與 SoftEther 進階帳號設定測試。

涵蓋:
- softether 的 AccountDetailSet / AccountRetrySet 命令組裝
- vpngate_config 的進階選項預設值
- VpnGateTabMixin 的自動連線判斷與「只套用一次進階設定」邏輯
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import softether
import vpngate_config as config
from tabs_vpngate import VpnGateTabMixin


# ------------------------------------------------------------ softether

def _client_capturing(monkeypatch):
    client = softether.SoftEtherClient(vpncmd_path="vpncmd")
    calls = []
    monkeypatch.setattr(client, "run", lambda *args: calls.append(args) or "")
    return client, calls


def test_account_detail_set_max_tcp(monkeypatch):
    client, calls = _client_capturing(monkeypatch)
    client.account_detail_set("VPN2", max_tcp=3)
    assert calls == [("AccountDetailSet", "VPN2", "/MAXTCP:3")]


def test_account_detail_set_without_max_tcp(monkeypatch):
    client, calls = _client_capturing(monkeypatch)
    client.account_detail_set("VPN2")
    assert calls == [("AccountDetailSet", "VPN2")]


def test_account_retry_set_default_disables_reconnect(monkeypatch):
    client, calls = _client_capturing(monkeypatch)
    client.account_retry_set("VPN2", num=0)
    assert calls == [("AccountRetrySet", "VPN2", "/NUM:0")]


def test_account_retry_set_with_interval(monkeypatch):
    client, calls = _client_capturing(monkeypatch)
    client.account_retry_set("VPN2", num=999, interval=3)
    assert calls == [("AccountRetrySet", "VPN2", "/NUM:999", "/INTERVAL:3")]


def test_advanced_option_defaults():
    """高級設置預設:不自動重連、TCP 連線數 3。"""
    assert config.ACCOUNT_MAX_TCP == 3
    assert config.ACCOUNT_RETRY_NUM == 0


# ------------------------------------------------------------ mixin

class _Stub(VpnGateTabMixin):
    """只提供自動連線邏輯所需的最小介面 (不建立 Qt 元件)。"""

    def __init__(self):
        self.vpn_assigning = False
        self.vpn_nic_names = []
        self.vpn_candidates = []
        self.current_interfaces = {}

    def t(self, text):
        return text

    def _vpn_log(self, message):
        pass

    def _vpn_nic_online(self, nic, interfaces):
        return bool(interfaces.get(nic, {}).get('ipv4'))

    def _vpn_run_bg(self, fn, done=None):
        raise AssertionError("此測試不應啟動背景指派")


class _FakeCheckBox:
    def __init__(self, checked):
        self._checked = checked

    def isChecked(self):
        return self._checked


def test_auto_connect_enabled_reads_checkbox():
    stub = _Stub()
    stub.chk_vpn_auto_connect = _FakeCheckBox(True)
    assert stub._vpn_auto_connect_enabled() is True
    stub.chk_vpn_auto_connect = _FakeCheckBox(False)
    assert stub._vpn_auto_connect_enabled() is False
    # 沒有核取方塊時視為關閉
    stub2 = _Stub()
    assert stub2._vpn_auto_connect_enabled() is False


def test_start_assign_silent_without_nics_is_noop():
    stub = _Stub()
    stub._vpn_start_assign(silent=True)
    assert stub.vpn_assigning is False


def test_start_assign_skips_online_nics():
    stub = _Stub()
    stub.vpn_nic_names = ["VPN2"]
    stub.current_interfaces = {"VPN2": {"ipv4": "10.0.0.1"}}
    stub._vpn_start_assign(silent=True)   # 已在線 -> 不應指派
    assert stub.vpn_assigning is False


class _FakeSE:
    def __init__(self):
        self.calls = []

    def account_detail_set(self, name, max_tcp=None):
        self.calls.append(("detail", name, max_tcp))

    def account_retry_set(self, name, num=0):
        self.calls.append(("retry", name, num))


def _configure_stub():
    stub = _Stub()
    stub.vpn_se = _FakeSE()
    stub.vpn_configured_nics = set()
    stub.vpn_config_lock = threading.Lock()
    stub._vpn_post = lambda fn, *args: fn(*args)
    return stub


def test_configure_account_applies_options_once():
    stub = _configure_stub()
    stub._vpn_configure_account("VPN2")
    stub._vpn_configure_account("VPN2")   # 第二次不應重複套用
    assert stub.vpn_se.calls == [
        ("detail", "VPN2", 3),
        ("retry", "VPN2", 0),
    ]
