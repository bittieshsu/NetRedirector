# -*- coding: utf-8 -*-
"""規則分頁 mixin (自 IntegratedApp.MainWindow 抽出)
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


class RulesTabMixin:
    def setup_rules_tab(self):
        layout = QVBoxLayout(self.tab_rules)
        self.group_rule_form = QGroupBox("")
        form_layout = QVBoxLayout()
        
        row1 = QHBoxLayout()
        self.bg_rule_type = QButtonGroup()
        self.rb_name = QRadioButton("Process Name")
        self.rb_name.setChecked(True)
        self.rb_pid = QRadioButton("PID")
        self.bg_rule_type.addButton(self.rb_name, 0)
        self.bg_rule_type.addButton(self.rb_pid, 1)
        self.ent_target = QLineEdit()
        self._reg("placeholder", self.ent_target, "例如: chrome.*;Game*.exe ，或 PID 1234")
        row1.addWidget(self.rb_name)
        row1.addWidget(self.rb_pid)
        lbl_target = QLabel("")
        self._reg("text", lbl_target, "目標:")
        row1.addWidget(lbl_target)
        row1.addWidget(self.ent_target)
        form_layout.addLayout(row1)
        
        row2 = QHBoxLayout()
        self.ent_hosts = QLineEdit()
        self._reg("placeholder", self.ent_hosts, "IP (預設 *)")
        self.ent_hosts.setText("*")
        self.ent_hosts.setFixedWidth(120)
        self.ent_ports = QLineEdit()
        self._reg("placeholder", self.ent_ports, "Port (預設 *)")
        self.ent_ports.setText("*")
        self.ent_ports.setFixedWidth(100)
        self.combo_proto = QComboBox()
        self.combo_proto.addItems(["BOTH", "TCP", "UDP"])
        self.combo_proto.setFixedWidth(80)
        row2.addWidget(QLabel("Hosts:"))
        row2.addWidget(self.ent_hosts)
        row2.addWidget(QLabel("Ports:"))
        row2.addWidget(self.ent_ports)
        row2.addWidget(QLabel("Proto:"))
        row2.addWidget(self.combo_proto)
        row2.addStretch()
        form_layout.addLayout(row2)

        row3 = QHBoxLayout()
        self.combo_action = QComboBox()
        self._reg("combo", self.combo_action, ["PROXY (轉發)", "DIRECT (直連)", "BLOCK (阻擋)"])
        self.combo_proxy = QComboBox()
        self.refresh_proxy_combobox()
        self.btn_rule_action = QPushButton("")
        self.btn_rule_action.clicked.connect(self.save_rule_action)
        self.btn_rule_cancel = QPushButton("")
        self._reg("text", self.btn_rule_cancel, "取消修改")
        self.btn_rule_cancel.clicked.connect(self.cancel_rule_edit)
        self.btn_rule_cancel.hide()
        lbl_action = QLabel("")
        self._reg("text", lbl_action, "動作:")
        lbl_proxy = QLabel("")
        self._reg("text", lbl_proxy, "指定代理:")
        row3.addWidget(lbl_action)
        row3.addWidget(self.combo_action)
        row3.addWidget(lbl_proxy)
        row3.addWidget(self.combo_proxy)
        row3.addWidget(self.btn_rule_action)
        row3.addWidget(self.btn_rule_cancel)
        form_layout.addLayout(row3)
        
        self.group_rule_form.setLayout(form_layout)
        layout.addWidget(self.group_rule_form)
        
        self.table_rules = QTableWidget()
        cols = ["ID", "類型", "目標", "Hosts", "Ports", "Proto", "動作", "代理"]
        self.table_rules.setColumnCount(len(cols))
        self._reg("headers", self.table_rules, cols)
        self.table_rules.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_rules.setColumnHidden(0, True) 
        self.table_rules.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows) 
        self.table_rules.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers) 
        self.table_rules.cellDoubleClicked.connect(self.on_rule_double_click)
        self.table_rules.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_rules.customContextMenuRequested.connect(self.show_rule_menu)
        layout.addWidget(self.table_rules)
        
        btn_row = QHBoxLayout()
        btn_del = QPushButton("")
        self._reg("text", btn_del, "刪除選中規則")
        btn_del.clicked.connect(self.del_rule)
        lbl_hint = QLabel("")
        self._reg("text", lbl_hint, "提示：雙擊規則列可編輯，或按右鍵開啟選單")
        lbl_hint.setStyleSheet("color: gray;")
        btn_row.addWidget(btn_del)
        btn_row.addStretch()
        btn_row.addWidget(lbl_hint)
        layout.addLayout(btn_row)

    def on_rule_double_click(self, row, col):
        if row < 0: return
        rule_id = int(self.table_rules.item(row, 0).text())
        rule_data = next((r for r in self.rules if r['id'] == rule_id), None)
        if not rule_data: return

        self.editing_rule_id = rule_id

        self.ent_target.setText(rule_data['target'])
        self.ent_hosts.setText(rule_data.get('hosts', '*'))
        self.ent_ports.setText(rule_data.get('ports', '*'))
        if rule_data['type'] == 'PID': self.rb_pid.setChecked(True)
        else: self.rb_name.setChecked(True)
        idx_proto = self.combo_proto.findText(rule_data.get('proto', 'BOTH'))
        if idx_proto >= 0: self.combo_proto.setCurrentIndex(idx_proto)
        self.combo_action.setCurrentIndex(self._rule_action_idx(rule_data))
        current_proxy_text = rule_data['proxy']
        idx_proxy = self.combo_proxy.findText(current_proxy_text)
        if idx_proxy >= 0: self.combo_proxy.setCurrentIndex(idx_proxy)
        else: self.combo_proxy.setCurrentIndex(0)
        self.update_form_titles()

    def _rule_action_idx(self, rule_data):
        key = rule_data.get('action_key')
        if key is not None:
            return int(key)
        a = rule_data.get('action', '')
        if "DIRECT" in a: return 1
        if "BLOCK" in a: return 2
        return 0

    def _action_display(self, rule_data):
        return self.t(["PROXY (轉發)", "DIRECT (直連)", "BLOCK (阻擋)"][self._rule_action_idx(rule_data)])

    def cancel_rule_edit(self):
        self.editing_rule_id = None
        self.ent_target.clear()
        self.ent_hosts.setText("*")
        self.ent_ports.setText("*")
        self.combo_proxy.setCurrentIndex(0)
        self.combo_action.setCurrentIndex(0)
        self.update_form_titles()

    def save_rule_action(self):
        # [Fixed] 正規化全形星號 (U+FF0A) 為半形，避免中文輸入法產生的規則永不匹配
        target = rule_utils.normalize_rule_target(self.ent_target.text())
        if not target: return
        hosts = rule_utils.normalize_rule_pattern(self.ent_hosts.text())
        ports = rule_utils.normalize_rule_pattern(self.ent_ports.text())
        proto_str = self.combo_proto.currentText()
        protocol = RuleProtocol.BOTH
        if proto_str == "TCP": protocol = RuleProtocol.TCP
        elif proto_str == "UDP": protocol = RuleProtocol.UDP

        is_pid = self.rb_pid.isChecked()
        action_idx = self.combo_action.currentIndex()
        action_text = self.combo_action.currentText()
        pid_proxy = self.combo_proxy.currentData() or 0
        pid_proxy = int(pid_proxy)
        proxy_text = self.combo_proxy.currentText()
        was_edit = self.editing_rule_id is not None

        # [改進] 編輯規則時優先「原地更新」(EditRuleWithProxy 保留相同 ID)，
        # 避免規則 ID 跳動；僅「PID 規則」或「名稱/PID 類型切換」才需刪除重建
        # (C 核心的 EditRuleWithProxy 不處理 target_pid 欄位)
        rid = 0
        if was_edit:
            old_rule = next((r for r in self.rules if r['id'] == self.editing_rule_id), None)
            old_is_pid = bool(old_rule and old_rule.get('type') == 'PID')
            edit_fn = getattr(self.bridge.lib, 'NetRedirector_EditRuleWithProxy', None)

            if edit_fn is not None and not is_pid and not old_is_pid:
                ok = edit_fn(
                    self.editing_rule_id,
                    target.encode('utf-8'),
                    hosts.encode('utf-8'),
                    ports.encode('utf-8'),
                    protocol,
                    action_idx,
                    pid_proxy,
                )
                if ok:
                    rid = self.editing_rule_id  # ID 不變，原地生效
                else:
                    # 原地更新失敗 → 回退為刪除+重建
                    self.bridge.lib.NetRedirector_DeleteRule(self.editing_rule_id)
                    self.rules = [r for r in self.rules if r['id'] != self.editing_rule_id]
            else:
                if hasattr(self.bridge.lib, 'NetRedirector_DeleteRule'):
                    self.bridge.lib.NetRedirector_DeleteRule(self.editing_rule_id)
                self.rules = [r for r in self.rules if r['id'] != self.editing_rule_id]
                logging.info(f"正在更新規則 ID {self.editing_rule_id} -> 先行刪除")

        if rid == 0:
            if is_pid:
                if not target.isdigit():
                    QMessageBox.warning(self, self.t("錯誤"), self.t("PID 需為數字"))
                    return
                rid = self.bridge.add_rule_by_pid(int(target), hosts, ports, protocol, action_idx, pid_proxy)
            else:
                if hasattr(self.bridge.lib, 'NetRedirector_AddRuleWithProxy'):
                     rid = self.bridge.lib.NetRedirector_AddRuleWithProxy(
                        target.encode('utf-8'), hosts.encode('utf-8'), ports.encode('utf-8'), protocol, action_idx, pid_proxy
                    )
                else:
                    rid = self.bridge.add_rule(target, hosts, ports, protocol, action_idx)
        
        if rid > 0:
            new_rule = {
                'id': rid,
                'type': 'PID' if is_pid else 'Name',
                'target': target,
                'hosts': hosts,
                'ports': ports,
                'proto': proto_str,
                'action': action_text,
                'action_key': action_idx,
                'proxy': proxy_text
            }
            if was_edit and rid == self.editing_rule_id:
                # 原地更新：取代對應項目，保持 ID 不變
                self.rules = [new_rule if r['id'] == rid else r for r in self.rules]
            else:
                self.rules.append(new_rule)
            self.refresh_rules_table()
            self.cancel_rule_edit()
            self.append_log(f"規則已{'更新' if was_edit else '新增'} (ID: {rid})")
        else:
            QMessageBox.warning(self, self.t("失敗"), self.t("驅動返回錯誤，規則添加失敗。"))

    def del_rule(self):
        row = self.table_rules.currentRow()
        if row < 0: return
        rid = int(self.table_rules.item(row, 0).text())
        self.bridge.lib.NetRedirector_DeleteRule(rid)
        self.rules = [r for r in self.rules if r['id'] != rid]
        self.refresh_rules_table()

    def refresh_rules_table(self):
        self.table_rules.setRowCount(0)
        for r in self.rules:
            row = self.table_rules.rowCount()
            self.table_rules.insertRow(row)
            self.table_rules.setItem(row, 0, QTableWidgetItem(str(r['id'])))
            self.table_rules.setItem(row, 1, QTableWidgetItem(r['type']))
            self.table_rules.setItem(row, 2, QTableWidgetItem(r['target']))
            self.table_rules.setItem(row, 3, QTableWidgetItem(r.get('hosts', '*')))
            self.table_rules.setItem(row, 4, QTableWidgetItem(r.get('ports', '*')))
            self.table_rules.setItem(row, 5, QTableWidgetItem(r.get('proto', 'BOTH')))
            self.table_rules.setItem(row, 6, QTableWidgetItem(self._action_display(r)))
            self.table_rules.setItem(row, 7, QTableWidgetItem(r['proxy']))

