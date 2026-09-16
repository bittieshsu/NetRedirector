# -*- coding: utf-8 -*-
"""規則分頁 UI 元件測試 — 對話框資料收集與進程挑選。

以 Qt offscreen 平台執行，不顯示視窗、不需要管理員權限與 DLL。
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication, QDialog

import tabs_rules


def _app():
    return QApplication.instance() or QApplication([])


def test_rule_dialog_collects_name_rule():
    _app()
    dialog = tabs_rules.RuleDialog(
        None, proxy_choices=[("[Custom] P1", 7), ("[Hub] Local Port 30678", 9)])
    dialog.ent_target.setText("chrome.exe")
    dialog.rb_name.setChecked(True)
    dialog.ent_hosts.setText("*.google.com")
    dialog.ent_ports.setText("443")
    dialog.combo_proto.setCurrentIndex(1)     # TCP
    dialog.combo_action.setCurrentIndex(1)    # DIRECT
    dialog.combo_proxy.setCurrentIndex(0)

    data = dialog.get_data()
    assert data["type"] == "Name"
    assert data["target"] == "chrome.exe"
    assert data["hosts"] == "*.google.com"
    assert data["ports"] == "443"
    assert data["proto"] == "TCP"
    assert data["action_idx"] == 1
    assert data["proxy_id"] == 7


def test_rule_dialog_normalizes_fullwidth_asterisk():
    _app()
    dialog = tabs_rules.RuleDialog(None, proxy_choices=[])
    dialog.ent_target.setText("game.exe")
    dialog.ent_hosts.setText("\uff0a")  # 全形星號，應正規化為半形
    assert dialog.get_data()["hosts"] == "*"


def test_rule_dialog_shows_hosts_and_ports_hint():
    """Hosts/Ports 留空時應顯示示例 placeholder，送出時仍回預設 "*"。"""
    _app()
    dialog = tabs_rules.RuleDialog(None, proxy_choices=[])
    assert dialog.ent_hosts.text() == ""
    assert dialog.ent_hosts.placeholderText()
    assert dialog.ent_ports.text() == ""
    assert dialog.ent_ports.placeholderText()

    dialog.ent_target.setText("chrome.exe")
    data = dialog.get_data()
    assert data["hosts"] == "*"
    assert data["ports"] == "*"


def test_rule_dialog_blank_target_defaults_to_all_processes():
    """目標留空時應顯示示例 placeholder，送出時預設為 "*" (所有進程)。"""
    _app()
    dialog = tabs_rules.RuleDialog(None, proxy_choices=[])
    assert dialog.ent_target.text() == ""
    assert dialog.ent_target.placeholderText()
    assert dialog.get_data()["target"] == "*"


def test_rule_dialog_prefills_for_edit():
    _app()
    rule = {
        "id": 42, "enabled": True, "type": "PID", "target": "1234",
        "hosts": "*", "ports": "*", "proto": "UDP", "action_key": 2,
        "action": "BLOCK (阻擋)", "proxy": "[Custom] P1", "proxy_name": "custom:P1",
    }
    dialog = tabs_rules.RuleDialog(
        None, rule_data=rule, proxy_choices=[("[Custom] P1", 7)])
    data = dialog.get_data()
    assert data["type"] == "PID"
    assert data["target"] == "1234"
    assert data["proto"] == "UDP"
    assert data["action_idx"] == 2
    assert data["proxy_id"] == 7


def test_rule_dialog_default_target_prefill():
    _app()
    name_dialog = tabs_rules.RuleDialog(
        None, proxy_choices=[], default_target="steam.exe")
    assert name_dialog.get_data()["type"] == "Name"
    assert name_dialog.get_data()["target"] == "steam.exe"

    pid_dialog = tabs_rules.RuleDialog(
        None, proxy_choices=[], default_target="4321", default_is_pid=True)
    assert pid_dialog.get_data()["type"] == "PID"
    assert pid_dialog.get_data()["target"] == "4321"


def test_rule_dialog_reload_proxies_keeps_selection():
    _app()
    dialog = tabs_rules.RuleDialog(
        None, proxy_choices=[("[Custom] A", 1), ("[Custom] B", 2)])
    dialog.combo_proxy.setCurrentIndex(1)
    dialog.reload_proxies([("[Custom] A", 1), ("[Custom] B", 2), ("[Hub] 30678", 3)])
    assert dialog.combo_proxy.currentData() == 2


def test_process_picker_filter_hides_non_matching():
    _app()
    dialog = tabs_rules.ProcessPickerDialog(None)
    if dialog.table.rowCount() == 0:
        return  # 無進程可測 (非 Windows 或 API 失敗)
    first_name = dialog.table.item(0, 0).text()
    dialog.ent_filter.setText(first_name)
    visible = [row for row in range(dialog.table.rowCount())
               if not dialog.table.isRowHidden(row)]
    assert visible, "過濾後至少應留下符合的列"
    for row in visible:
        assert first_name.lower() in dialog.table.item(row, 0).text().lower()


def test_process_picker_without_selection_returns_empty():
    _app()
    dialog = tabs_rules.ProcessPickerDialog(None)
    dialog.table.setCurrentItem(None)
    assert dialog.selected_process() == ("", 0)


def test_process_picker_mode_selection():
    _app()
    dialog = tabs_rules.ProcessPickerDialog(None)
    assert dialog.selected_mode() == "Name"   # 預設以進程名稱為目標

    pid_default = tabs_rules.ProcessPickerDialog(None, default_mode="PID")
    assert pid_default.selected_mode() == "PID"

    name_default = tabs_rules.ProcessPickerDialog(None, default_mode="Name")
    assert name_default.selected_mode() == "Name"


def test_process_picker_confirm_buttons_pick_target_type():
    """確認按鈕即目標類型：按下「使用 PID」應以 PID 接受對話框。"""
    _app()
    dialog = tabs_rules.ProcessPickerDialog(None)
    assert not hasattr(dialog, "rb_pid")       # 類型選項已改為按鈕
    if dialog.table.rowCount() == 0:
        return  # 無進程可選 (非 Windows 或 API 失敗)
    dialog.table.setCurrentCell(0, 0)
    dialog.btn_use_pid.click()
    assert dialog.selected_mode() == "PID"
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_action_index_falls_back_to_action_text():
    assert tabs_rules._rule_action_index({"action_key": 2}) == 2
    assert tabs_rules._rule_action_index({"action": "DIRECT (直連)"}) == 1
    assert tabs_rules._rule_action_index({"action": "BLOCK (阻擋)"}) == 2
    assert tabs_rules._rule_action_index({}) == 0
