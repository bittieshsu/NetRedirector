# -*- coding: utf-8 -*-
"""監控分頁/右鍵選單/服務控制 mixin (自 IntegratedApp.MainWindow 抽出)
"""

import time
import logging
import ctypes
import os
import json
from datetime import datetime

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QLabel, QGroupBox, QSpinBox, QTextEdit,
                             QListWidget, QSplitter, QMessageBox, QHeaderView,
                             QTabWidget, QComboBox, QLineEdit, QRadioButton, QButtonGroup, QMenu)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QColor, QBrush, QAction

from i18n import i18n as tr, SUPPORTED_LANGS
import network_utils
import proxy_core
import secure_config
import rule_utils
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol


class MonitorTabMixin:
    def setup_monitor_tab(self):
        layout = QVBoxLayout(self.tab_monitor)
        cols = ["Time", "Process", "PID", "Destination", "Info"]
        self.tree_traffic = QTableWidget()
        self.tree_traffic.setColumnCount(len(cols))
        self.tree_traffic.setHorizontalHeaderLabels(cols)
        self.tree_traffic.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tree_traffic.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_traffic.customContextMenuRequested.connect(self.show_traffic_menu)
        layout.addWidget(self.tree_traffic)
        
        btn_clear = QPushButton("")
        self._reg("text", btn_clear, "清除記錄")
        btn_clear.clicked.connect(lambda: self.tree_traffic.setRowCount(0))
        layout.addWidget(btn_clear)

    # (其他邏輯函式，如 add_hub_port, refresh_hub_table 等，保持不變)
    def show_rule_menu(self, pos):
        row = self.table_rules.rowAt(pos.y())
        if row < 0: return
        self.table_rules.selectRow(row)
        menu = QMenu()
        act_edit = QAction(self.t("編輯規則"), self)
        act_edit.triggered.connect(lambda: self.on_rule_double_click(row, 0))
        act_del = QAction(self.t("刪除規則"), self)
        act_del.triggered.connect(self.del_rule)
        menu.addAction(act_edit)
        menu.addAction(act_del)
        menu.exec(self.table_rules.viewport().mapToGlobal(pos))

    def show_proxy_menu(self, pos):
        row = self.table_custom_proxies.rowAt(pos.y())
        if row < 0: return
        self.table_custom_proxies.selectRow(row)
        menu = QMenu()
        act_edit = QAction(self.t("編輯代理"), self)
        act_edit.triggered.connect(lambda: self.on_proxy_double_click(row, 0))
        act_del = QAction(self.t("刪除代理"), self)
        act_del.triggered.connect(self.del_custom_proxy)
        menu.addAction(act_edit)
        menu.addAction(act_del)
        menu.exec(self.table_custom_proxies.viewport().mapToGlobal(pos))

    def show_traffic_menu(self, pos):
        item = self.tree_traffic.itemAt(pos)
        if not item: return
        row = item.row()
        pid = self.tree_traffic.item(row, 2).text()
        proc = self.tree_traffic.item(row, 1).text()
        menu = QMenu()
        act_pid = QAction(self.t("為 PID {pid} 新增規則").format(pid=pid), self)
        act_pid.triggered.connect(lambda: self.quick_add_rule(pid, True))
        act_proc = QAction(self.t("為 {proc} 新增規則").format(proc=proc), self)
        act_proc.triggered.connect(lambda: self.quick_add_rule(proc, False))
        menu.addAction(act_pid)
        menu.addAction(act_proc)
        menu.exec(self.tree_traffic.viewport().mapToGlobal(pos))

    def quick_add_rule(self, target, is_pid):
        self.tabs.setCurrentIndex(1)
        self.ent_target.setText(str(target))
        if is_pid: self.rb_pid.setChecked(True)
        else: self.rb_name.setChecked(True)

# [新增] 強制重刷規則到 DLL (解決啟動後規則不生效的問題)
    def _rule_proxy_id(self, rule):
        combo_idx = self.combo_proxy.findText(rule['proxy'])
        if combo_idx >= 0:
            return int(self.combo_proxy.itemData(combo_idx))
        return 0

    def reapply_all_rules(self, only_proxy_id=None):
        if not self.rules:
            return

        # 若指定 only_proxy_id，只重刷引用該代理的規則（例如編輯代理後 ID 變更時）
        if only_proxy_id is not None:
            target_rules = [r for r in self.rules if self._rule_proxy_id(r) == only_proxy_id]
        else:
            target_rules = self.rules
        if not target_rules:
            return

        self.append_log("正在重新套用所有規則以確保生效...")
        
        # 為了避免在迭代時修改列表導致問題，我們建立一個暫存的新列表
        refreshed_rules = []
        
        for r in self.rules:
            if r not in target_rules:
                refreshed_rules.append(r)
                continue
            
            old_id = r['id']
            
            # 1. 先嘗試刪除舊的 (如果存在)
            # 注意：如果 DLL 在 Start 時清空了內部列表，這步可能無效但無害
            if hasattr(self.bridge.lib, 'NetRedirector_DeleteRule'):
                try:
                    self.bridge.lib.NetRedirector_DeleteRule(old_id)
                except:
                    pass

            # 2. 準備參數重新加入
            target = r['target']
            hosts = r.get('hosts', '*')
            ports = r.get('ports', '*')
            
            # 還原 Protocol 枚舉
            proto_str = r.get('proto', 'BOTH')
            protocol = RuleProtocol.BOTH
            if proto_str == "TCP": protocol = RuleProtocol.TCP
            elif proto_str == "UDP": protocol = RuleProtocol.UDP

            # 還原 Action 與 Proxy
            # 注意：我們需要重新查找 Proxy ID，因為如果 Proxy 也重刷了，ID 可能會變
            # 但在此修正案中，我們假設 Proxy Config 在 Start 前載入是有效的 (通常 Proxy Config 不依賴驅動 Handle)
            # 如果 Proxy 也失效，這裡需要類似邏輯處理 Proxy，但通常只有 Rule 需要。
            
            action_idx = self._rule_action_idx(r)
            
            # 嘗試從 UI 文字找回 Proxy ID (因為 ID 可能在重啟程式後變更)
            # [修正] 若代理已被刪除/重新加入，這裡會解析到最新的 ID，讓新帳密立即生效
            proxy_id = self._rule_proxy_id(r)

            # 3. 呼叫 DLL 加入規則 (這會觸發 UpdateFilter)
            new_rid = 0
            if r['type'] == 'PID':
                new_rid = self.bridge.add_rule_by_pid(int(target), hosts, ports, protocol, action_idx, int(proxy_id))
            else:
                if hasattr(self.bridge.lib, 'NetRedirector_AddRuleWithProxy'):
                    new_rid = self.bridge.lib.NetRedirector_AddRuleWithProxy(
                        target.encode('utf-8'), hosts.encode('utf-8'), ports.encode('utf-8'), protocol, action_idx, int(proxy_id)
                    )
                else:
                    new_rid = self.bridge.add_rule(target, hosts, ports, protocol, action_idx)

            # 4. 更新規則資料中的 ID
            if new_rid > 0:
                r['id'] = new_rid
                refreshed_rules.append(r)
                logging.debug(f"規則 '{target}' 已重刷，新 ID: {new_rid}")
            else:
                self.append_log(f"[錯誤] 無法重刷規則: {target}")
                # 即使失敗也保留舊資料，避免介面清空
                refreshed_rules.append(r)

        # 更新記憶體中的列表
        self.rules = refreshed_rules
        # 更新介面上的 ID 顯示
        self.refresh_rules_table()
        self.append_log(f"已重新套用 {len(self.rules)} 條規則。")

    def toggle_redirector_service(self):
        # 檢查按鈕目前的狀態 (因為是 checkable，點擊後狀態已經改變)
        is_checked = self.btn_master_switch.isChecked()
        
        if is_checked:
            # === 嘗試啟動 ===
            if self.bridge.start():
                self.is_redirector_running = True
                self.update_service_status()
                logging.info("NetRedirector Started")
                
                # [關鍵修正] 啟動成功後，立即重刷所有規則
                # 這會強制 DLL 重新產生 WinDivert Filter String
                self.reapply_all_rules()
                
            else:
                # 啟動失敗，將按鈕彈回
                self.btn_master_switch.setChecked(False)
                QMessageBox.critical(self, self.t("錯誤"), self.t("無法啟動驅動，請確認管理員權限或驅動檔案是否存在。"))
        else:
            # === 停止服務 ===
            self.bridge.stop()
            self.is_redirector_running = False
            self.update_service_status()
            logging.info("NetRedirector Stopped")

