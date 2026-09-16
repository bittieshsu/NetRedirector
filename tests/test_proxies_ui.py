# -*- coding: utf-8 -*-
"""代理分頁 UI 元件測試 — ProxyDialog 資料收集。

以 Qt offscreen 平台執行，不顯示視窗、不需要管理員權限與 DLL。
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication

import tabs_proxies


def _app():
    return QApplication.instance() or QApplication([])


def test_proxy_dialog_collects_data():
    _app()
    dialog = tabs_proxies.ProxyDialog(None)
    dialog.ent_name.setText("  MyVPN  ")
    dialog.combo_type.setCurrentIndex(1)   # HTTP
    dialog.ent_ip.setText(" 1.2.3.4 ")
    dialog.ent_port.setText(" 3128 ")
    dialog.ent_user.setText("u")
    dialog.ent_pass.setText("p")

    data = dialog.get_data()
    assert data["name"] == "MyVPN"      # 前後空白應去除
    assert data["type"] == "HTTP"
    assert data["ip"] == "1.2.3.4"
    assert data["port"] == "3128"
    assert data["user"] == "u"
    assert data["pass"] == "p"          # 密碼原樣保留


def test_proxy_dialog_prefills_for_edit():
    _app()
    proxy = {
        "id": 7, "name": "JP Node", "type": "SOCKS5", "ip": "10.0.0.1",
        "port": 1080, "user": "vip", "pass": "secret", "latency": "-",
    }
    dialog = tabs_proxies.ProxyDialog(None, proxy_data=proxy)
    data = dialog.get_data()
    assert data["name"] == "JP Node"
    assert data["type"] == "SOCKS5"
    assert data["ip"] == "10.0.0.1"
    assert data["port"] == "1080"
    assert data["user"] == "vip"
    assert data["pass"] == "secret"


def test_proxy_dialog_edit_button_label():
    _app()
    add_dialog = tabs_proxies.ProxyDialog(None)
    assert add_dialog.btn_save.objectName() == "PrimaryBtn"
    edit_dialog = tabs_proxies.ProxyDialog(
        None, proxy_data={"id": 1, "name": "n", "type": "HTTP",
                          "ip": "i", "port": 1, "user": "", "pass": ""})
    assert edit_dialog.btn_save.objectName() == "WarnBtn"


def test_status_emoji_mapping():
    assert tabs_proxies._STATUS_EMOJI["green"] == "🟢"
    assert tabs_proxies._STATUS_EMOJI["orange"] == "🟡"
    assert tabs_proxies._STATUS_EMOJI["red"] == "🔴"
