# -*- coding: utf-8 -*-
"""代理分頁 mixin (自 IntegratedApp.MainWindow 抽出)

版面自 demo_modern_ui.py 的代理分頁移植：工具列 + 全寬表格，
表單改為彈出式對話框 (不再常駐佔用分頁垂直空間)。
"""

import time
import threading
import traceback

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QPushButton, QLabel,
                             QMessageBox, QHeaderView, QComboBox, QLineEdit,
                             QDialog, QFormLayout, QAbstractItemView)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush

from i18n import i18n as tr
import proxy_core  # noqa: F401 — 模組化測試要求 mixin 模組可解析此名稱
import ui_theme
from app_helpers import check_proxy_connection  # [Fixed] test_all_proxies 需要
from NetRedirector import ProxyType


# DLL 回報的延遲狀態 → 表格顯示的燈號
_STATUS_EMOJI = {"green": "🟢", "orange": "🟡", "red": "🔴"}


class ProxyDialog(QDialog):
    """新增 / 編輯外部代理對話框。

    對齊 demo_modern_ui 的彈窗形式：表單不再常駐於分頁，代理清單可以
    佔滿整個分頁高度。
    """

    def __init__(self, parent=None, proxy_data=None):
        super().__init__(parent)
        self._editing = proxy_data is not None
        self.setWindowTitle(
            tr.t("編輯代理 (ID: {pid})").format(pid=proxy_data.get('id', 0))
            if self._editing else tr.t("新增外部代理 (SOCKS5/HTTP)"))
        self.resize(460, 320)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        form = QFormLayout()
        form.setSpacing(12)

        self.ent_name = QLineEdit()
        self.ent_name.setPlaceholderText(tr.t("名稱 (例: MyVPN)"))
        form.addRow(tr.t("名稱:"), self.ent_name)

        self.combo_type = QComboBox()
        self.combo_type.addItems(["SOCKS5", "HTTP"])
        form.addRow(tr.t("類型:"), self.combo_type)

        self.ent_ip = QLineEdit()
        self.ent_ip.setPlaceholderText(tr.t("IP 地址"))
        form.addRow(tr.t("IP Host:"), self.ent_ip)

        self.ent_port = QLineEdit()
        self.ent_port.setPlaceholderText(tr.t("Port"))
        form.addRow(tr.t("Port:"), self.ent_port)

        self.ent_user = QLineEdit()
        self.ent_user.setPlaceholderText(tr.t("驗證帳號 (選填)"))
        form.addRow(tr.t("User:"), self.ent_user)

        self.ent_pass = QLineEdit()
        self.ent_pass.setPlaceholderText(tr.t("驗證密碼 (選填)"))
        self.ent_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(tr.t("Pass:"), self.ent_pass)

        layout.addLayout(form)
        layout.addStretch()

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_cancel = QPushButton(tr.t("取消修改"))
        btn_cancel.clicked.connect(self.reject)
        self.btn_save = QPushButton(
            tr.t("保存修改") if self._editing else tr.t("新增代理"))
        ui_theme.set_button_kind(
            self.btn_save, "WarnBtn" if self._editing else "PrimaryBtn")
        self.btn_save.clicked.connect(self.accept)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(self.btn_save)
        layout.addLayout(btn_box)

        if self._editing:
            self._load(proxy_data)

    def _load(self, proxy_data):
        self.ent_name.setText(proxy_data.get('name', ''))
        idx = self.combo_type.findText(proxy_data.get('type', 'SOCKS5'))
        if idx >= 0:
            self.combo_type.setCurrentIndex(idx)
        self.ent_ip.setText(proxy_data.get('ip', ''))
        self.ent_port.setText(str(proxy_data.get('port', '')))
        self.ent_user.setText(proxy_data.get('user', ''))
        self.ent_pass.setText(proxy_data.get('pass', ''))

    def get_data(self):
        """收集表單內容 (去除前後空白；密碼原樣保留)。"""
        return {
            'name': self.ent_name.text().strip(),
            'type': self.combo_type.currentText(),
            'ip': self.ent_ip.text().strip(),
            'port': self.ent_port.text().strip(),
            'user': self.ent_user.text(),
            'pass': self.ent_pass.text(),
        }


class ProxiesTabMixin:
    def setup_custom_proxy_tab(self):
        layout = QVBoxLayout(self.tab_proxies)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # ---------- 工具列 ----------
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.btn_add_proxy = QPushButton("")
        self.btn_add_proxy.setObjectName("PrimaryBtn")
        self._reg("text", self.btn_add_proxy, "➕ 新增自訂代理")
        self.btn_add_proxy.clicked.connect(lambda: self.open_add_proxy_dialog())
        toolbar.addWidget(self.btn_add_proxy)

        self.btn_test_proxies = QPushButton("")
        self._reg("text", self.btn_test_proxies, "⚡ 批次測速 Ping 全部")
        self.btn_test_proxies.clicked.connect(self.test_all_proxies)
        toolbar.addWidget(self.btn_test_proxies)

        self.btn_del_proxy = QPushButton("")
        self._reg("text", self.btn_del_proxy, "🗑 刪除選取")
        self.btn_del_proxy.clicked.connect(self.del_custom_proxy)
        toolbar.addWidget(self.btn_del_proxy)

        toolbar.addSpacing(16)

        self.ent_proxy_search = QLineEdit()
        self.ent_proxy_search.setFixedWidth(240)
        self._reg("placeholder", self.ent_proxy_search, "🔍 快速搜尋代理...")
        self.ent_proxy_search.textChanged.connect(self.apply_proxy_filter)
        toolbar.addWidget(self.ent_proxy_search)

        toolbar.addStretch()
        lbl_hint = QLabel("")
        self._reg("text", lbl_hint, "💡 提示：雙擊代理列可編輯，或按右鍵開啟選單")
        lbl_hint.setStyleSheet("color: #64748B; font-size: 12px;")
        toolbar.addWidget(lbl_hint)
        layout.addLayout(toolbar)

        # ---------- 代理表格 ----------
        self.table_custom_proxies = QTableWidget()
        cols = ["ID", "名稱", "類型", "IP:Port", "驗證", "延遲"]
        self.table_custom_proxies.setColumnCount(len(cols))
        self._reg("headers", self.table_custom_proxies, cols)
        self.table_custom_proxies.verticalHeader().setVisible(False)
        # 短欄位依內容自動收合，名稱(變動文字)才伸展
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch)
        self.table_custom_proxies.setColumnHidden(0, True)
        self.table_custom_proxies.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_custom_proxies.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_custom_proxies.cellDoubleClicked.connect(self.on_proxy_double_click)
        self.table_custom_proxies.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_custom_proxies.customContextMenuRequested.connect(self.show_proxy_menu)
        layout.addWidget(self.table_custom_proxies)

    # ----------------------------------------------------------- 下拉清單
    def refresh_proxy_combobox(self):
        """代理下拉改由規則對話框即時建立 (見 RulesTabMixin.proxy_choices)。

        規則表單不再常駐，因此沒有可更新的常駐 combo；保留此方法作為各處
        呼叫的相容入口，並在規則對話框開著時同步其代理清單。
        """
        dialog = getattr(self, '_rule_dialog', None)
        if dialog is not None and dialog.isVisible():
            dialog.reload_proxies(self.proxy_choices())

    # ----------------------------------------------------------- 對話框
    def open_add_proxy_dialog(self):
        dialog = ProxyDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.apply_proxy_dialog_data(dialog.get_data(), None)

    def open_edit_proxy_dialog(self, proxy_data):
        dialog = ProxyDialog(self, proxy_data=proxy_data)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.apply_proxy_dialog_data(dialog.get_data(), proxy_data)

    def on_proxy_double_click(self, row, col):
        if 0 <= row < len(self.custom_proxies):
            self.open_edit_proxy_dialog(self.custom_proxies[row])

    def apply_proxy_dialog_data(self, data, editing_proxy):
        """把對話框內容寫入 DLL 與記憶體清單 (新增或原地更新)。"""
        name = data['name']
        ip = data['ip']
        port_str = data['port']
        user = data['user']
        pwd = data['pass']
        ptype_str = data['type']
        if not name or not ip or not port_str:
            QMessageBox.warning(self, self.t("警告"), self.t("名稱、IP 與 Port 為必填"))
            return
        try:
            port = int(port_str)
        except ValueError:
            QMessageBox.warning(self, self.t("警告"), self.t("名稱、IP 與 Port 為必填"))
            return
        ptype = ProxyType.SOCKS5 if ptype_str == "SOCKS5" else ProxyType.HTTP

        old_proxy_id = editing_proxy['id'] if editing_proxy is not None else None

        # [根因修正] 編輯代理「原地更新」：EditProxyConfig 保留相同 proxy ID，
        # 已建立的規則仍指向同一 ID，新帳密立即對所有規則生效，不需重刷規則
        if old_proxy_id is not None:
            edit_fn = getattr(self.bridge.lib, 'NetRedirector_EditProxyConfig', None)
            if edit_fn is not None:
                old_name = next(
                    (p['name'] for p in self.custom_proxies if p['id'] == old_proxy_id),
                    None)
                ok = edit_fn(
                    old_proxy_id,
                    ptype,
                    name.encode('utf-8'),
                    ip.encode('utf-8'),
                    port,
                    user.encode('utf-8'),
                    pwd.encode('utf-8'),
                    True  # enabled
                )
                if ok:
                    for p in self.custom_proxies:
                        if p['id'] == old_proxy_id:
                            p.update({'name': name, 'type': ptype_str, 'ip': ip,
                                      'port': port, 'user': user, 'pass': pwd})
                    # [Fixed] 改名時同步置換引用此代理的規則 (新舊前綴與舊版
                    # 無前綴都要比對): 否則存檔後規則仍指向舊名稱, 下次啟動
                    # 代理解析落空 → 規則靜默退回直連
                    if old_name is not None and old_name != name:
                        new_ref = f"custom:{name}"
                        old_refs = (f"custom:{old_name}", old_name)
                        for r in self.rules:
                            if r.get('proxy_name') in old_refs:
                                r['proxy_name'] = new_ref
                                r['proxy'] = f"[Custom] {name}"
                        self.refresh_rules_table()
                        self.append_log(
                            f"代理更名 {old_name} → {name}，已同步更新引用它的規則")
                    self.refresh_custom_proxy_table()
                    self.refresh_proxy_combobox()
                    self.append_log(f"自訂代理已更新 (ID 不變，立即生效): {name}")
                    return
                QMessageBox.warning(self, self.t("失敗"), self.t("DLL 無法更新代理配置"))
                return

            # 舊版 DLL 沒有 EditProxyConfig 的 fallback：刪除+重建（ID 會變，需重刷規則）
            if hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
                self.bridge.lib.NetRedirector_DeleteProxyConfig(old_proxy_id)
            self.custom_proxies = [
                p for p in self.custom_proxies if p['id'] != old_proxy_id]

        pid = self.bridge.add_proxy(ip, port, user, pwd, ptype, name)
        if pid > 0:
            self.custom_proxies.append({
                'id': pid,
                'name': name,
                'type': ptype_str,
                'ip': ip,
                'port': port,
                'user': user,
                'pass': pwd,
                'latency': '-'
            })
            self.refresh_custom_proxy_table()
            self.refresh_proxy_combobox()
            self.append_log(f"自訂代理已新增: {name}")
            # 只有 fallback 刪除+重建路徑才需要重刷引用舊 ID 的規則
            if old_proxy_id is not None and pid != old_proxy_id:
                self.append_log(
                    f"代理 ID 已變更 ({old_proxy_id} -> {pid})，重刷引用該代理的規則...")
                self.reapply_all_rules(only_proxy_id=old_proxy_id)
        else:
            QMessageBox.warning(self, self.t("失敗"), self.t("DLL 無法添加代理配置"))

    # ----------------------------------------------------------- 批次測速
    def test_all_proxies(self):
        self.append_log("開始測試所有自訂代理 (目標: api.ipify.org)...")

        def worker_func():
            try:
                for p in self.custom_proxies:
                    try:
                        success, ms, result = check_proxy_connection(p)
                        if success:
                            p['latency'] = f"{ms}ms (IP: {result})"
                            p['status_color'] = "green" if ms < 500 else "orange"
                            self.redir_signals.log_received.emit(
                                f"測試成功: {p['name']} -> {result}")
                        else:
                            err_msg = str(result)
                            if "timed out" in err_msg:
                                err_msg = "超時"
                            elif "refused" in err_msg:
                                err_msg = "連線被拒"
                            p['latency'] = f"失敗: {err_msg}"
                            p['status_color'] = "red"
                    except Exception as e_inner:  # noqa: BLE001 — 單一代理失敗不中斷整批
                        p['latency'] = f"錯誤: {str(e_inner)}"
                        p['status_color'] = "red"
                    self.update_proxy_table_signal.emit()
                    time.sleep(0.05)
                self.redir_signals.log_received.emit("所有代理測試完成。")
            except Exception:  # noqa: BLE001 — 背景執行緒需自行回報
                err_trace = traceback.format_exc()
                self.redir_signals.log_received.emit(f"測試線程嚴重崩潰:\n{err_trace}")

        threading.Thread(target=worker_func, daemon=True).start()

    def del_custom_proxy(self):
        row = self.table_custom_proxies.currentRow()
        if not (0 <= row < len(self.custom_proxies)):
            return
        proxy = self.custom_proxies[row]
        pid = int(proxy['id'])
        if hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
            self.bridge.lib.NetRedirector_DeleteProxyConfig(pid)
        self.custom_proxies = [p for p in self.custom_proxies if p is not proxy]
        self.refresh_custom_proxy_table()
        self.refresh_proxy_combobox()
        # [修正] 代理被刪除後，引用它的規則若不重刷會殘留失效的 proxy ID
        self.reapply_all_rules(only_proxy_id=pid)

    # ----------------------------------------------------------- 表格
    def refresh_custom_proxy_table(self):
        scroll = self.table_custom_proxies.verticalScrollBar().value()
        self.table_custom_proxies.setRowCount(0)
        for p in self.custom_proxies:
            row = self.table_custom_proxies.rowCount()
            self.table_custom_proxies.insertRow(row)
            self.table_custom_proxies.setItem(row, 0, QTableWidgetItem(str(p['id'])))
            self.table_custom_proxies.setItem(row, 1, QTableWidgetItem(p['name']))
            self.table_custom_proxies.setItem(row, 2, QTableWidgetItem(p['type']))
            self.table_custom_proxies.setItem(
                row, 3, QTableWidgetItem(f"{p['ip']}:{p['port']}"))
            auth = "Yes" if p['user'] else "No"
            self.table_custom_proxies.setItem(row, 4, QTableWidgetItem(auth))

            lat_str = str(p.get('latency', '-'))
            color_code = p.get('status_color', '')
            emoji = _STATUS_EMOJI.get(color_code, "")
            lat_item = QTableWidgetItem(f"{emoji} {lat_str}" if emoji else lat_str)
            if color_code == "green":
                lat_item.setForeground(QBrush(QColor(ui_theme.COLOR_SUCCESS)))
                lat_item.setToolTip(
                    f"測試成功，出口 IP: {lat_str.split('IP:')[-1].strip(')')}")
            elif color_code == "orange":
                lat_item.setForeground(QBrush(QColor(ui_theme.COLOR_WARN)))
            elif color_code == "red":
                lat_item.setForeground(QBrush(QColor(ui_theme.COLOR_DANGER)))
                lat_item.setToolTip(lat_str)
            else:
                lat_item.setForeground(QBrush(QColor("#64748B")))
            self.table_custom_proxies.setItem(row, 5, lat_item)
        self.apply_proxy_filter()
        self.table_custom_proxies.verticalScrollBar().setValue(scroll)

    def _proxy_row_matches(self, row):
        keyword = self.ent_proxy_search.text().strip().lower()
        if not keyword:
            return True
        for col in (1, 2, 3, 4):
            item = self.table_custom_proxies.item(row, col)
            if item and keyword in item.text().lower():
                return True
        return False

    def apply_proxy_filter(self):
        for row in range(self.table_custom_proxies.rowCount()):
            self.table_custom_proxies.setRowHidden(
                row, not self._proxy_row_matches(row))
