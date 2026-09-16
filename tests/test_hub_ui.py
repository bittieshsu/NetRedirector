# -*- coding: utf-8 -*-
"""Hub 分頁 UI 元件測試 — 綁定表格的整列點擊切換。

以 Qt offscreen 平台執行，不顯示視窗、不需要管理員權限與 DLL。
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget

from tabs_hub import HubTabMixin


class _Stub(HubTabMixin):
    """只提供 setup_hub_tab / refresh_hub_table 所需的最小介面。"""

    def __init__(self):
        self.tab_hub = QWidget()
        self.port_config = {}
        self.current_interfaces = {}
        self.hub_proxy_map = {}
        self.selected_hub_port = None

    def _reg(self, *args):
        pass

    def t(self, text):
        return text

    def append_log(self, message):
        pass


def _app():
    return QApplication.instance() or QApplication([])


def _stub(bound=(), interfaces=()):
    _app()
    stub = _Stub()
    stub.setup_hub_tab()
    stub.selected_hub_port = 30678
    stub.port_config[30678] = list(bound)
    stub.current_interfaces = {
        name: {"ipv4": "10.0.0.%d" % (i + 1), "latency": 50}
        for i, name in enumerate(interfaces)
    }
    stub.refresh_hub_table()
    return stub


def _row_of(table, name):
    for row in range(table.rowCount()):
        if table.item(row, 1).text() == name:
            return row
    raise AssertionError("表格中找不到介面 %s" % name)


def _is_checked(table, row):
    return table.item(row, 0).checkState() == Qt.CheckState.Checked


def test_hub_table_reflects_existing_binding():
    stub = _stub(bound=["VPN-A"], interfaces=["VPN-A", "Ethernet"])
    table = stub.table_hub
    assert _is_checked(table, _row_of(table, "VPN-A"))
    assert not _is_checked(table, _row_of(table, "Ethernet"))


def test_click_other_column_toggles_binding():
    stub = _stub(bound=["VPN-A"], interfaces=["VPN-A", "Ethernet"])
    table = stub.table_hub
    row = _row_of(table, "Ethernet")

    stub.on_hub_table_click(row, 1)          # 點介面名稱欄
    assert _is_checked(table, row)
    assert "Ethernet" in stub.port_config[30678]

    stub.on_hub_table_click(row, 4)          # 再點一次負載欄 -> 取消
    assert not _is_checked(table, row)
    assert "Ethernet" not in stub.port_config[30678]


def test_click_blank_area_of_checkbox_column_toggles_binding():
    """回歸:點在「綁定」欄但沒對準勾選框時,以前完全沒有反應。"""
    stub = _stub(bound=[], interfaces=["VPN-A"])
    table = stub.table_hub
    row = _row_of(table, "VPN-A")
    assert not _is_checked(table, row)

    stub.on_hub_table_click(row, 0)          # Qt 不會自動切換,由 handler 補上
    assert _is_checked(table, row)
    assert stub.port_config[30678] == ["VPN-A"]

    stub.on_hub_table_click(row, 0)
    assert not _is_checked(table, row)
    assert stub.port_config[30678] == []


def test_click_on_indicator_is_not_toggled_twice():
    """點到指示器本體時 Qt 已先切換,handler 只能沿用、不可再翻轉。"""
    stub = _stub(bound=[], interfaces=["VPN-A"])
    table = stub.table_hub
    row = _row_of(table, "VPN-A")

    # Qt 的自動切換:先套用新狀態,再發出 cellClicked
    table.item(row, 0).setCheckState(Qt.CheckState.Checked)
    stub.on_hub_table_click(row, 0)
    assert _is_checked(table, row)
    assert stub.port_config[30678] == ["VPN-A"]

    # 反向:Qt 已取消勾選
    table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
    stub.on_hub_table_click(row, 0)
    assert not _is_checked(table, row)
    assert stub.port_config[30678] == []


def test_binding_update_reaches_route_manager():
    import proxy_core

    stub = _stub(bound=[], interfaces=["VPN-A"])
    row = _row_of(stub.table_hub, "VPN-A")
    stub.on_hub_table_click(row, 0)
    assert proxy_core.route_manager.port_bindings[30678] == ["VPN-A"]
