import sys
import time
import logging
import ctypes
import os
import json  # [新增] 用於儲存設定
from datetime import datetime

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem, 
                             QPushButton, QLabel, QGroupBox, QSpinBox, QTextEdit, 
                             QListWidget, QSplitter, QMessageBox, QHeaderView,
                             QTabWidget, QComboBox, QLineEdit, QRadioButton, QButtonGroup, QMenu)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QColor, QBrush, QAction

from i18n import i18n as tr, SUPPORTED_LANGS

# 匯入現有的模組
import network_utils
import proxy_core
import secure_config  # [新增] 密碼 DPAPI 加密儲存
import rule_utils  # [模組化] 規則欄位處理 (全形星號正規化等)
from app_helpers import (  # [模組化] GUI 輔助元件 (自本檔抽出)
    check_proxy_connection, SignalLogHandler, NetworkMonitorWorker, RedirectorSignals,
)
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol
from tabs_hub import HubTabMixin
from tabs_rules import RulesTabMixin
from tabs_proxies import ProxiesTabMixin
from tabs_monitor import MonitorTabMixin

class MainWindow(QMainWindow, HubTabMixin, RulesTabMixin, ProxiesTabMixin, MonitorTabMixin):
    update_proxy_table_signal = Signal() 
    CONFIG_FILE = "config.json"  # [新增] 設定檔路徑

    def __init__(self):
        super().__init__()
        self._i18n_registry = []
        self.setWindowTitle(self.t("NetRedirector x GameProxyHub 整合專業版"))
        self._reg("window", self, "NetRedirector x GameProxyHub 整合專業版")
        self.resize(1024, 768)
        dll_path = "NetRedirector.dll"
        
        try:
            self.bridge = NetRedirectorWrapper(dll_path)
        except Exception as e:
            sys.exit(1)

        # 核心數據結構
        self.port_config = {}      # Hub: { port: [interface_names] }
        self.hub_proxy_map = {}    # Hub Port -> Proxy ID
        self.custom_proxies = []   # List of dict: Manual Proxies
        self.rules = []            # Rules list
        self.current_interfaces = {}
        self.selected_hub_port = None
        self.is_redirector_running = False
        self.editing_proxy_id = None
        self.editing_rule_id = None

        # 設置 Redirector 回調
        self.redir_signals = RedirectorSignals()
        self.redir_signals.log_received.connect(self.on_dll_log)
        self.redir_signals.traffic_received.connect(self.on_traffic_event)
        
        self.bridge.set_log_callback(self.redir_signals.log_received.emit)
        self.bridge.set_connection_callback(self.redir_signals.traffic_received.emit)

        # [新增] 可配置的 Ping 目標 (需在 setup_ui 之前初始化，UI 會引用)
        self.ping_target = network_utils.PING_TARGET

        # UI 初始化
        self.setup_ui()
        
        # 啟動網路監控
        self.monitor_thread = NetworkMonitorWorker(self.ping_target)
        self.monitor_thread.data_updated.connect(self.on_network_update)
        self.monitor_thread.start()
        
        # Log Handler
        self.log_handler = SignalLogHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - [Hub] %(message)s', datefmt='%H:%M:%S'))
        self.log_handler.log_signal.connect(self.append_log)
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.INFO)

        self.update_proxy_table_signal.connect(self.refresh_custom_proxy_table)

        # [新增] 載入設定
        QTimer.singleShot(100, self.load_config)

        self.append_log("系統就緒。")

    # --- 多國語系支援 ---
    def t(self, s):
        return tr.t(s)

    def _reg(self, kind, *args):
        self._i18n_registry.append((kind, args))
        self._apply_i18n(kind, args)

    def _apply_i18n(self, kind, args):
        if kind == "text":
            args[0].setText(self.t(args[1]))
        elif kind == "title":
            args[0].setTitle(self.t(args[1]))
        elif kind == "placeholder":
            args[0].setPlaceholderText(self.t(args[1]))
        elif kind == "combo":
            combo, keys = args
            idx = combo.currentIndex()
            combo.blockSignals(True)
            combo.clear()
            combo.addItems([self.t(k) for k in keys])
            if idx >= 0 and idx < len(keys):
                combo.setCurrentIndex(idx)
            combo.blockSignals(False)
        elif kind == "headers":
            tbl, keys = args
            tbl.setHorizontalHeaderLabels([self.t(k) for k in keys])
        elif kind == "tab":
            args[0].setTabText(args[1], self.t(args[2]))
        elif kind == "window":
            args[0].setWindowTitle(self.t(args[1]))

    def retranslate_ui(self):
        for kind, args in self._i18n_registry:
            self._apply_i18n(kind, args)
        self.update_service_status()
        self.update_hub_status()
        self.update_form_titles()
        self.refresh_proxy_combobox()
        self.refresh_rules_table()
        self.refresh_custom_proxy_table()
        self.refresh_hub_table()
        idx = self.combo_lang.findData(tr.lang)
        if idx >= 0 and idx != self.combo_lang.currentIndex():
            self.combo_lang.blockSignals(True)
            self.combo_lang.setCurrentIndex(idx)
            self.combo_lang.blockSignals(False)

    def on_lang_changed(self, idx):
        code = self.combo_lang.itemData(idx)
        if code and code != tr.lang:
            tr.load(code)
            self.retranslate_ui()
            self.append_log(f"語言已切換: {tr.lang_name(code)}")

    # [新增] Ping 目標變更 (即時套用至監控執行緒，並於下次存檔時寫入 config.json)
    def on_ping_target_changed(self):
        target = self.ent_ping_target.text().strip()
        if not target:
            target = network_utils.PING_TARGET
            self.ent_ping_target.setText(target)
        if target != self.ping_target:
            self.ping_target = target
            self.monitor_thread.set_ping_target(target)
            self.append_log(f"Ping 目標已更新: {target}")

    def update_service_status(self):
        running = self.is_redirector_running
        self.btn_master_switch.setText(
            self.t("停止攔截服務 (Stop)") if running else self.t("啟動攔截服務 (Start Redirector)"))
        self.btn_master_switch.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold; padding: 6px;" if running
            else "background-color: #f44336; color: white; font-weight: bold; padding: 6px;")
        self.lbl_status.setText(self.t("狀態: 運行中") if running else self.t("狀態: 停止"))
        self.lbl_status.setStyleSheet("color: green; font-weight: bold;" if running else "color: red; font-weight: bold;")

    def update_hub_status(self):
        if self.selected_hub_port:
            self.lbl_hub_status.setText(self.t("當前端口: {port}").format(port=self.selected_hub_port))
        else:
            self.lbl_hub_status.setText(self.t("未選擇端口"))

    def update_form_titles(self):
        if self.editing_rule_id is not None:
            self.group_rule_form.setTitle(self.t("編輯規則 (ID: {rule_id})").format(rule_id=self.editing_rule_id))
            self.btn_rule_action.setText(self.t("保存修改"))
            self.btn_rule_action.setStyleSheet("background-color: #FF9800; color: white; font-weight: bold;")
            self.btn_rule_cancel.show()
        else:
            self.group_rule_form.setTitle(self.t("新增攔截規則"))
            self.btn_rule_action.setText(self.t("新增規則"))
            self.btn_rule_action.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
            self.btn_rule_cancel.hide()
        if self.editing_proxy_id is not None:
            self.group_proxy_form.setTitle(self.t("編輯代理 (ID: {pid})").format(pid=self.editing_proxy_id))
            self.btn_proxy_save.setText(self.t("保存修改"))
            self.btn_proxy_save.setStyleSheet("background-color: #FF9800; color: white;")
            self.btn_proxy_cancel.show()
        else:
            self.group_proxy_form.setTitle(self.t("新增外部代理 (SOCKS5/HTTP)"))
            self.btn_proxy_save.setText(self.t("新增代理"))
            self.btn_proxy_save.setStyleSheet("background-color: #2196F3; color: white;")
            self.btn_proxy_cancel.hide()

    # [新增] 儲存設定功能
    def save_config(self):
        config_data = {
            "lang": tr.lang,
            "ping_target": self.ping_target,  # [新增] 儲存 Ping 目標
            "hubs": self.port_config,
            "proxies": [],
            "rules": []
        }

        # 序列化 Proxy (移除動態數據如 latency, ID；密碼以 DPAPI 加密存放)
        for p in self.custom_proxies:
            config_data["proxies"].append({
                "name": p['name'],
                "type": p['type'],
                "ip": p['ip'],
                "port": p['port'],
                "user": p['user'],
                "pass": secure_config.encrypt_password(p['pass'])
            })

        # 序列化 Rules (需要保存 Proxy 的辨識字串，而非動態 ID)
        for r in self.rules:
            config_data["rules"].append({
                "type": r['type'],
                "target": r['target'],
                "hosts": r.get('hosts', '*'),
                "ports": r.get('ports', '*'),
                "proto": r.get('proto', 'BOTH'),
                "action": r['action'],
                "action_key": r.get('action_key'),
                "proxy_text": r['proxy'] # 這裡保存 UI 上顯示的 Proxy 文字 (例如 "[Custom] MyVPN")
            })

        try:
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            self.append_log("設定已儲存至 config.json")
        except Exception as e:
            self.append_log(f"儲存設定失敗: {e}")

    # [新增] 讀取設定功能
    def load_config(self):
        if not os.path.exists(self.CONFIG_FILE):
            return

        try:
            with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)

            saved_lang = data.get("lang")
            if saved_lang:
                tr.load(saved_lang)

            # [新增] 還原 Ping 目標 (若設定檔未提供則使用預設)
            saved_ping = data.get("ping_target", "")
            if saved_ping:
                self.ping_target = saved_ping
                self.monitor_thread.set_ping_target(saved_ping)
                if hasattr(self, 'ent_ping_target'):
                    self.ent_ping_target.setText(saved_ping)

            self.append_log("正在還原設定...")

            # 1. 還原 Custom Proxies
            saved_proxies = data.get("proxies", [])
            for p in saved_proxies:
                ptype = ProxyType.SOCKS5 if p['type'] == "SOCKS5" else ProxyType.HTTP
                plain_pass = secure_config.decrypt_password(p.get('pass', ''))  # [新增] 解密儲存的密碼
                pid = self.bridge.add_proxy(p['ip'], int(p['port']), p['user'], plain_pass, ptype, p['name'])
                if pid > 0:
                    self.custom_proxies.append({
                        'id': pid, # 取得新的 ID
                        'name': p['name'],
                        'type': p['type'],
                        'ip': p['ip'],
                        'port': p['port'],
                        'user': p['user'],
                        'pass': plain_pass,
                        'latency': '-'
                    })
            self.refresh_custom_proxy_table()

            # 2. 還原 Hubs
            saved_hubs = data.get("hubs", {})
            for port_str, interfaces in saved_hubs.items():
                port = int(port_str)
                self.port_config[port] = interfaces
                self.list_hub_ports.addItem(f"{port}")
                
                # 自動啟動 Hub
                proxy_core.route_manager.update_port_binding(port, interfaces)
                success = proxy_core.server_controller.start_port(port)
                self.update_hub_list_item(port, success)
                if success:
                    self.sync_hub_proxy(port)
            
            # 確保 SpinBox 不會跟現有重複
            if saved_hubs:
                max_port = max([int(p) for p in saved_hubs.keys()])
                self.spin_hub_port.setValue(max_port + 1)

            # 更新下拉選單，以便還原 Rules 時能找到對應的 Proxy
            self.refresh_proxy_combobox()

            # 3. 還原 Rules
            saved_rules = data.get("rules", [])
            for r in saved_rules:
                # 嘗試根據 proxy_text 找回對應的 新ID
                proxy_text = r['proxy_text']
                proxy_id = 0 # 預設 Direct/Unspecified
                
                # 在 combo box 尋找對應的 ID
                idx = self.combo_proxy.findText(proxy_text)
                if idx >= 0:
                    proxy_id = self.combo_proxy.itemData(idx)
                
                # 協議轉換
                protocol = RuleProtocol.BOTH
                if r['proto'] == "TCP": protocol = RuleProtocol.TCP
                elif r['proto'] == "UDP": protocol = RuleProtocol.UDP

                # 動作轉換
                action_key = r.get('action_key')
                if action_key is None:
                    action_key = 0
                    if "DIRECT" in r['action']: action_key = 1
                    elif "BLOCK" in r['action']: action_key = 2
                action_idx = action_key

                # 呼叫 DLL
                rid = 0
                # [Fixed] 正規化設定檔中可能存在的全形星號 (U+FF0A)
                target = rule_utils.normalize_rule_target(r['target'])
                hosts = rule_utils.normalize_rule_pattern(r.get('hosts'))
                ports = rule_utils.normalize_rule_pattern(r.get('ports'))
                
                if r['type'] == 'PID':
                    if target.isdigit():
                        rid = self.bridge.add_rule_by_pid(int(target), hosts, ports, protocol, action_idx, int(proxy_id))
                else:
                    if hasattr(self.bridge.lib, 'NetRedirector_AddRuleWithProxy'):
                        rid = self.bridge.lib.NetRedirector_AddRuleWithProxy(
                            target.encode('utf-8'), hosts.encode('utf-8'), ports.encode('utf-8'), protocol, action_idx, int(proxy_id)
                        )
                    else:
                        rid = self.bridge.add_rule(target, hosts, ports, protocol, action_idx)

                if rid > 0:
                    self.rules.append({
                        'id': rid,
                        'type': r['type'],
                        'target': target,
                        'hosts': hosts,
                        'ports': ports,
                        'proto': r['proto'],
                        'action': r['action'],
                        'action_key': action_key,
                        'proxy': proxy_text # 保持原本的顯示文字
                    })

            self.refresh_rules_table()
            self.append_log(f"設定還原完成: 代理 {len(self.custom_proxies)} 個, 路由 {len(self.port_config)} 個, 規則 {len(self.rules)} 條")
            self.retranslate_ui()

        except Exception as e:
            self.append_log(f"還原設定失敗: {e}")
            import traceback
            traceback.print_exc()

    # (原本的 setup_ui 等函式保持不變，省略...)
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 頂部控制列
        top_bar = QHBoxLayout()
        self.btn_master_switch = QPushButton("")
        self.btn_master_switch.setCheckable(True)
        self.btn_master_switch.clicked.connect(self.toggle_redirector_service)
        top_bar.addWidget(self.btn_master_switch)
        
        self.lbl_status = QLabel("")
        top_bar.addWidget(self.lbl_status)

        self.combo_lang = QComboBox()
        self.combo_lang.setFixedWidth(150)
        for code in SUPPORTED_LANGS:
            self.combo_lang.addItem(tr.lang_name(code), code)
        self.combo_lang.currentIndexChanged.connect(self.on_lang_changed)

        # [新增] Ping 目標設定 (預設 8.8.8.8，可依地區改為其他目標)
        lbl_ping = QLabel("")
        self._reg("text", lbl_ping, "Ping 目標:")
        self.ent_ping_target = QLineEdit(self.ping_target)
        self.ent_ping_target.setFixedWidth(120)
        self.ent_ping_target.setToolTip("網路介面延遲偵測的 Ping 目標 (IP 或域名)")
        self.ent_ping_target.editingFinished.connect(self.on_ping_target_changed)

        top_bar.addStretch()
        top_bar.addWidget(lbl_ping)
        top_bar.addWidget(self.ent_ping_target)
        top_bar.addWidget(self.combo_lang)
        main_layout.addLayout(top_bar)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.tab_hub = QWidget()
        self.setup_hub_tab()
        self.tabs.addTab(self.tab_hub, "")
        self._reg("tab", self.tabs, 0, "1. 端口路由管理 (Hub)")

        self.tab_rules = QWidget()
        self.setup_rules_tab()
        self.tabs.addTab(self.tab_rules, "")
        self._reg("tab", self.tabs, 1, "2. 進程攔截規則 (Rules)")

        self.tab_proxies = QWidget()
        self.setup_custom_proxy_tab()
        self.tabs.addTab(self.tab_proxies, "")
        self._reg("tab", self.tabs, 2, "3. 自訂代理管理 (Proxies)")

        self.tab_monitor = QWidget()
        self.setup_monitor_tab()
        self.tabs.addTab(self.tab_monitor, "")
        self._reg("tab", self.tabs, 3, "4. 流量監控 (Monitor)")

        log_group = QGroupBox("")
        self._reg("title", log_group, "系統日誌")
        log_layout = QVBoxLayout()
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        log_layout.addWidget(self.txt_log)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)
        
        main_layout.setStretch(1, 4) 
        main_layout.setStretch(2, 1)

        self.update_service_status()
        self.update_hub_status()
        self.update_form_titles()

    # (以下為各 Tab 的 setup 函式，與原版相同)
    def on_network_update(self, interfaces):
        self.current_interfaces = interfaces
        proxy_core.route_manager.sync_interfaces(interfaces)
        if self.tabs.currentIndex() == 0:
            self.refresh_hub_table()

    def on_traffic_event(self, process, pid, ip, port, info):
        if pid == os.getpid():
            return  # 不顯示本程式自己產生的流量
        if self.tree_traffic.rowCount() > 500:
            self.tree_traffic.removeRow(0)
        row = self.tree_traffic.rowCount()
        self.tree_traffic.insertRow(row)
        self.tree_traffic.setItem(row, 0, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self.tree_traffic.setItem(row, 1, QTableWidgetItem(process))
        self.tree_traffic.setItem(row, 2, QTableWidgetItem(str(pid)))
        self.tree_traffic.setItem(row, 3, QTableWidgetItem(f"{ip}:{port}"))
        self.tree_traffic.setItem(row, 4, QTableWidgetItem(info))
        self.tree_traffic.scrollToBottom()

    def on_dll_log(self, msg):
        self.append_log(f"[DLL] {msg}")

    def append_log(self, msg):
        self.txt_log.append(msg)
        c = self.txt_log.textCursor()
        c.movePosition(c.MoveOperation.End)
        self.txt_log.setTextCursor(c)

    # [新增] 在關閉時儲存設定
    def closeEvent(self, event):
        self.save_config() # 儲存設定
        self.monitor_thread.stop()
        if self.is_redirector_running:
            self.bridge.stop()
        proxy_core.server_controller.stop_all()
        event.accept()

if __name__ == '__main__':
    try: is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except: is_admin = False
    
    app = QApplication(sys.argv)
    if not is_admin:
        QMessageBox.warning(None, tr.t("權限不足"), tr.t("請以管理員身分執行！"))
        sys.exit(1)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())