import sys
import time
import logging
import ctypes
import socket
import os
import json  # [新增] 用於儲存設定
from datetime import datetime

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem, 
                             QPushButton, QLabel, QGroupBox, QSpinBox, QTextEdit, 
                             QListWidget, QSplitter, QMessageBox, QHeaderView,
                             QTabWidget, QComboBox, QLineEdit, QRadioButton, QButtonGroup, QMenu)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QObject
from PySide6.QtGui import QColor, QBrush, QAction

import socket
import struct
import base64
import time

# 匯入現有的模組
import network_utils
import proxy_core
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol

# ... (check_proxy_connection 函式保持不變，省略以節省篇幅) ...
def check_proxy_connection(proxy_conf):
    """
    使用 socket 實作 SOCKS5/HTTP 協議，經由代理訪問 http://api.ipify.org
    """
    # 這裡直接複製你原本的 check_proxy_connection 程式碼即可
    target_host = "api.ipify.org"
    target_port = 80
    
    ip = proxy_conf['ip']
    port = int(proxy_conf['port'])
    user = proxy_conf.get('user', '')
    pwd = proxy_conf.get('pass', '')
    ptype = proxy_conf['type']
    
    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    
    try:
        s.connect((ip, port))
        if ptype == "SOCKS5":
            # [修正] 只要有帳或密，就同時提供 no-auth + user/pass 兩種方法，
            # 讓伺服器決定；避免「只送 no-auth、伺服器要求認證」被回 0xFF
            if user or pwd:
                s.sendall(b'\x05\x02\x00\x02')
            else:
                s.sendall(b'\x05\x01\x00')
            resp = s.recv(2)
            if not resp or resp[0] != 0x05: raise Exception("無效的 SOCKS5 回應")
            if resp[1] == 0x02:
                if not user: raise Exception("代理需要驗證但未提供帳密")
                auth_payload = b'\x01' + bytes([len(user)]) + user.encode() + bytes([len(pwd)]) + pwd.encode()
                s.sendall(auth_payload)
                auth_resp = s.recv(2)
                if not auth_resp or auth_resp[1] != 0x00: raise Exception("帳號或密碼錯誤")
            elif resp[1] != 0x00:
                raise Exception("不支援的驗證方式")

            cmd = b'\x05\x01\x00\x03' + bytes([len(target_host)]) + target_host.encode() + struct.pack("!H", target_port)
            s.sendall(cmd)
            resp = s.recv(4)
            if not resp or resp[1] != 0x00: raise Exception(f"SOCKS5 連線目標失敗 (Code: {resp[1] if resp else 'None'})")
            addr_type = resp[3]
            if addr_type == 1: s.recv(4)
            elif addr_type == 3: s.recv(1 + s.recv(1)[0])
            elif addr_type == 4: s.recv(16)
            s.recv(2)

        elif ptype == "HTTP":
            headers = [
                f"GET http://{target_host}/ HTTP/1.1",
                f"Host: {target_host}",
                "Connection: close"
            ]
            if user and pwd:
                credentials = f"{user}:{pwd}"
                b64_cred = base64.b64encode(credentials.encode()).decode()
                headers.append(f"Proxy-Authorization: Basic {b64_cred}")
            request = "\r\n".join(headers) + "\r\n\r\n"
            s.sendall(request.encode())

        if ptype == "SOCKS5":
            http_req = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
            s.sendall(http_req.encode())
            
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
            
        response_str = response.decode(errors='ignore')
        if "\r\n\r\n" in response_str:
            body = response_str.split("\r\n\r\n", 1)[1].strip()
        else:
            body = response_str.strip()
            
        if len(body) > 15 or len(body) < 7:
             if "407" in response_str: raise Exception("HTTP 407: 驗證失敗")
             if "403" in response_str: raise Exception("HTTP 403: 被拒絕")
        
        duration = int((time.time() - start_time) * 1000)
        s.close()
        return True, duration, body
    except Exception as e:
        s.close()
        return False, 0, str(e)


# --- 日誌處理 ---
class SignalLogHandler(logging.Handler, QObject):
    log_signal = Signal(str)

    def __init__(self):
        logging.Handler.__init__(self)
        QObject.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)

# --- 網路監控 ---
class NetworkMonitorWorker(QThread):
    data_updated = Signal(dict) 

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        while self.running:
            interfaces = network_utils.get_system_interfaces()
            for name, details in interfaces.items():
                if details['connected']:
                    details['latency'] = network_utils.ping_address(details['ipv4'], "8.8.8.8")
                else:
                    details['latency'] = 9999
            
            self.data_updated.emit(interfaces)
            for _ in range(30): 
                if not self.running: break
                time.sleep(0.1)

    def stop(self):
        self.running = False
        self.wait()

# --- NetRedirector 信號 ---
class RedirectorSignals(QObject):
    log_received = Signal(str)
    traffic_received = Signal(str, int, str, int, str)

class MainWindow(QMainWindow):
    update_proxy_table_signal = Signal() 
    CONFIG_FILE = "config.json"  # [新增] 設定檔路徑

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetRedirector x GameProxyHub 整合專業版")
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

        # UI 初始化
        self.setup_ui()
        
        # 啟動網路監控
        self.monitor_thread = NetworkMonitorWorker()
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

    # [新增] 儲存設定功能
    def save_config(self):
        config_data = {
            "hubs": self.port_config,
            "proxies": [],
            "rules": []
        }

        # 序列化 Proxy (移除動態數據如 latency, ID)
        for p in self.custom_proxies:
            config_data["proxies"].append({
                "name": p['name'],
                "type": p['type'],
                "ip": p['ip'],
                "port": p['port'],
                "user": p['user'],
                "pass": p['pass']
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

            self.append_log("正在還原設定...")

            # 1. 還原 Custom Proxies
            saved_proxies = data.get("proxies", [])
            for p in saved_proxies:
                ptype = ProxyType.SOCKS5 if p['type'] == "SOCKS5" else ProxyType.HTTP
                pid = self.bridge.add_proxy(p['ip'], int(p['port']), p['user'], p['pass'], ptype, p['name'])
                if pid > 0:
                    self.custom_proxies.append({
                        'id': pid, # 取得新的 ID
                        'name': p['name'],
                        'type': p['type'],
                        'ip': p['ip'],
                        'port': p['port'],
                        'user': p['user'],
                        'pass': p['pass'],
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
                action_idx = 0 # Default Proxy
                if "DIRECT" in r['action']: action_idx = 1
                elif "BLOCK" in r['action']: action_idx = 2

                # 呼叫 DLL
                rid = 0
                target = r['target']
                hosts = r.get('hosts', '*')
                ports = r.get('ports', '*')
                
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
                        'proxy': proxy_text # 保持原本的顯示文字
                    })

            self.refresh_rules_table()
            self.append_log(f"設定還原完成: 代理 {len(self.custom_proxies)} 個, 路由 {len(self.port_config)} 個, 規則 {len(self.rules)} 條")

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
        self.btn_master_switch = QPushButton("啟動攔截服務 (Start Redirector)")
        self.btn_master_switch.setCheckable(True)
        self.btn_master_switch.setStyleSheet("background-color: #f44336; color: white; font-weight: bold; padding: 6px;")
        self.btn_master_switch.clicked.connect(self.toggle_redirector_service)
        top_bar.addWidget(self.btn_master_switch)
        
        self.lbl_status = QLabel("攔截服務狀態: 停止")
        self.lbl_status.setStyleSheet("color: red; font-weight: bold;")
        top_bar.addWidget(self.lbl_status)
        top_bar.addStretch()
        main_layout.addLayout(top_bar)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.tab_hub = QWidget()
        self.setup_hub_tab()
        self.tabs.addTab(self.tab_hub, "1. 端口路由管理 (Hub)")

        self.tab_rules = QWidget()
        self.setup_rules_tab()
        self.tabs.addTab(self.tab_rules, "2. 進程攔截規則 (Rules)")

        self.tab_proxies = QWidget()
        self.setup_custom_proxy_tab()
        self.tabs.addTab(self.tab_proxies, "3. 自訂代理管理 (Proxies)")

        self.tab_monitor = QWidget()
        self.setup_monitor_tab()
        self.tabs.addTab(self.tab_monitor, "4. 流量監控 (Monitor)")

        log_group = QGroupBox("系統日誌")
        log_layout = QVBoxLayout()
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        log_layout.addWidget(self.txt_log)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)
        
        main_layout.setStretch(1, 4) 
        main_layout.setStretch(2, 1)

    # (以下為各 Tab 的 setup 函式，與原版相同)
    def setup_hub_tab(self):
        layout = QHBoxLayout(self.tab_hub)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QGroupBox("本地監聽端口")
        left_layout = QVBoxLayout()
        input_layout = QHBoxLayout()
        self.spin_hub_port = QSpinBox()
        self.spin_hub_port.setRange(1000, 65535)
        self.spin_hub_port.setValue(30678)
        btn_add = QPushButton("新增")
        btn_add.clicked.connect(self.add_hub_port)
        input_layout.addWidget(self.spin_hub_port)
        input_layout.addWidget(btn_add)
        
        self.list_hub_ports = QListWidget()
        self.list_hub_ports.itemClicked.connect(self.on_hub_port_selected)
        
        btn_del = QPushButton("刪除端口")
        btn_del.clicked.connect(self.del_hub_port)
        
        self.btn_apply_hub = QPushButton("啟動/重啟選中端口")
        self.btn_apply_hub.setStyleSheet("background-color: #4CAF50; color: white;")
        self.btn_apply_hub.clicked.connect(self.apply_hub_config)

        left_layout.addLayout(input_layout)
        left_layout.addWidget(self.list_hub_ports)
        left_layout.addWidget(self.btn_apply_hub)
        left_layout.addWidget(btn_del)
        left_panel.setLayout(left_layout)

        right_panel = QGroupBox("綁定出口網卡")
        right_layout = QVBoxLayout()
        self.lbl_hub_status = QLabel("未選擇端口")
        right_layout.addWidget(self.lbl_hub_status)
        
        filter_layout = QHBoxLayout()
        self.txt_hub_filter = QLineEdit()
        self.txt_hub_filter.setPlaceholderText("🔍 篩選介面 (例: VPN)")
        self.txt_hub_filter.textChanged.connect(self.refresh_hub_table) 
        
        btn_select_all_visible = QPushButton("全選顯示項目")
        btn_select_all_visible.clicked.connect(self.on_hub_select_all_visible)
        
        filter_layout.addWidget(self.txt_hub_filter)
        filter_layout.addWidget(btn_select_all_visible)
        right_layout.addLayout(filter_layout)

        self.table_hub = QTableWidget()
        self.table_hub.setColumnCount(5)
        self.table_hub.setHorizontalHeaderLabels(["綁定", "介面名稱", "IP", "延遲", "負載"])
        self.table_hub.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_hub.cellClicked.connect(self.on_hub_table_click)

        right_layout.addWidget(self.table_hub)
        right_panel.setLayout(right_layout)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

    def setup_rules_tab(self):
        layout = QVBoxLayout(self.tab_rules)
        self.group_rule_form = QGroupBox("新增攔截規則")
        form_layout = QVBoxLayout()
        
        row1 = QHBoxLayout()
        self.bg_rule_type = QButtonGroup()
        self.rb_name = QRadioButton("Process Name")
        self.rb_name.setChecked(True)
        self.rb_pid = QRadioButton("PID")
        self.bg_rule_type.addButton(self.rb_name, 0)
        self.bg_rule_type.addButton(self.rb_pid, 1)
        self.ent_target = QLineEdit()
        self.ent_target.setPlaceholderText("例如: chrome.*;Game*.exe ，或 PID 1234")
        row1.addWidget(self.rb_name)
        row1.addWidget(self.rb_pid)
        row1.addWidget(QLabel("目標:"))
        row1.addWidget(self.ent_target)
        form_layout.addLayout(row1)
        
        row2 = QHBoxLayout()
        self.ent_hosts = QLineEdit()
        self.ent_hosts.setPlaceholderText("IP (預設 *)")
        self.ent_hosts.setText("*")
        self.ent_hosts.setFixedWidth(120)
        self.ent_ports = QLineEdit()
        self.ent_ports.setPlaceholderText("Port (預設 *)")
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
        self.combo_action.addItems(["PROXY (轉發)", "DIRECT (直連)", "BLOCK (阻擋)"])
        self.combo_proxy = QComboBox()
        self.refresh_proxy_combobox()
        self.btn_rule_action = QPushButton("新增規則")
        self.btn_rule_action.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        self.btn_rule_action.clicked.connect(self.save_rule_action)
        self.btn_rule_cancel = QPushButton("取消修改")
        self.btn_rule_cancel.clicked.connect(self.cancel_rule_edit)
        self.btn_rule_cancel.hide()
        row3.addWidget(QLabel("動作:"))
        row3.addWidget(self.combo_action)
        row3.addWidget(QLabel("指定代理:"))
        row3.addWidget(self.combo_proxy)
        row3.addWidget(self.btn_rule_action)
        row3.addWidget(self.btn_rule_cancel)
        form_layout.addLayout(row3)
        
        self.group_rule_form.setLayout(form_layout)
        layout.addWidget(self.group_rule_form)
        
        self.table_rules = QTableWidget()
        cols = ["ID", "類型", "目標", "Hosts", "Ports", "Proto", "動作", "代理"]
        self.table_rules.setColumnCount(len(cols))
        self.table_rules.setHorizontalHeaderLabels(cols)
        self.table_rules.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_rules.setColumnHidden(0, True) 
        self.table_rules.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows) 
        self.table_rules.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers) 
        self.table_rules.cellDoubleClicked.connect(self.on_rule_double_click)
        layout.addWidget(self.table_rules)
        
        btn_del = QPushButton("刪除選中規則")
        btn_del.clicked.connect(self.del_rule)
        layout.addWidget(btn_del)

    def setup_custom_proxy_tab(self):
        layout = QVBoxLayout(self.tab_proxies)
        self.group_proxy_form = QGroupBox("新增外部代理 (SOCKS5/HTTP)")
        grid = QGridLayout()
        
        self.ent_cp_name = QLineEdit()
        self.ent_cp_name.setPlaceholderText("名稱 (例: MyVPN)")
        self.combo_cp_type = QComboBox()
        self.combo_cp_type.addItems(["SOCKS5", "HTTP"])
        grid.addWidget(QLabel("名稱:"), 0, 0)
        grid.addWidget(self.ent_cp_name, 0, 1)
        grid.addWidget(QLabel("類型:"), 0, 2)
        grid.addWidget(self.combo_cp_type, 0, 3)
        
        self.ent_cp_ip = QLineEdit()
        self.ent_cp_ip.setPlaceholderText("IP 地址")
        self.ent_cp_port = QLineEdit()
        self.ent_cp_port.setPlaceholderText("Port")
        self.ent_cp_port.setFixedWidth(80)
        grid.addWidget(QLabel("IP Host:"), 1, 0)
        grid.addWidget(self.ent_cp_ip, 1, 1)
        grid.addWidget(QLabel("Port:"), 1, 2)
        grid.addWidget(self.ent_cp_port, 1, 3)
        
        self.ent_cp_user = QLineEdit()
        self.ent_cp_user.setPlaceholderText("驗證帳號 (選填)")
        self.ent_cp_pass = QLineEdit()
        self.ent_cp_pass.setPlaceholderText("驗證密碼 (選填)")
        self.ent_cp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        grid.addWidget(QLabel("User:"), 2, 0)
        grid.addWidget(self.ent_cp_user, 2, 1)
        grid.addWidget(QLabel("Pass:"), 2, 2)
        grid.addWidget(self.ent_cp_pass, 2, 3)
        
        btn_layout = QHBoxLayout()
        self.btn_proxy_save = QPushButton("新增代理")
        self.btn_proxy_save.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        self.btn_proxy_save.clicked.connect(self.save_custom_proxy)
        self.btn_proxy_cancel = QPushButton("取消修改")
        self.btn_proxy_cancel.clicked.connect(self.cancel_proxy_edit)
        self.btn_proxy_cancel.hide()
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_proxy_cancel)
        btn_layout.addWidget(self.btn_proxy_save)
        grid.addLayout(btn_layout, 3, 0, 1, 4) 
        
        self.group_proxy_form.setLayout(grid)
        layout.addWidget(self.group_proxy_form)
        
        toolbar = QHBoxLayout()
        btn_test = QPushButton("測試所有代理連線 (Ping)")
        btn_test.clicked.connect(self.test_all_proxies)
        btn_del = QPushButton("刪除選中代理")
        btn_del.clicked.connect(self.del_custom_proxy)
        toolbar.addWidget(btn_test)
        toolbar.addStretch()
        toolbar.addWidget(btn_del)
        layout.addLayout(toolbar)

        self.table_custom_proxies = QTableWidget()
        cols = ["ID", "名稱", "類型", "IP:Port", "驗證", "延遲"]
        self.table_custom_proxies.setColumnCount(len(cols))
        self.table_custom_proxies.setHorizontalHeaderLabels(cols)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_custom_proxies.setColumnHidden(0, True)
        self.table_custom_proxies.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_custom_proxies.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_custom_proxies.cellDoubleClicked.connect(self.on_proxy_double_click)
        layout.addWidget(self.table_custom_proxies)

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
        
        btn_clear = QPushButton("清除記錄")
        btn_clear.clicked.connect(lambda: self.tree_traffic.setRowCount(0))
        layout.addWidget(btn_clear)

    # (其他邏輯函式，如 add_hub_port, refresh_hub_table 等，保持不變)
    def add_hub_port(self):
        port = self.spin_hub_port.value()
        if port in self.port_config: return
        self.port_config[port] = []
        self.list_hub_ports.addItem(f"{port}")
        self.spin_hub_port.setValue(port + 1)
        self.sync_hub_proxy(port)

    def del_hub_port(self):
        item = self.list_hub_ports.currentItem()
        if not item: return
        port = int(item.text().split()[0])
        proxy_core.server_controller.stop_port(port)
        if port in self.port_config: del self.port_config[port]
        if port in self.hub_proxy_map: del self.hub_proxy_map[port]
        self.list_hub_ports.takeItem(self.list_hub_ports.row(item))
        self.selected_hub_port = None
        self.refresh_hub_table()
        self.refresh_proxy_combobox()

    def on_hub_port_selected(self, item):
        if not item: return
        self.selected_hub_port = int(item.text().split()[0])
        self.lbl_hub_status.setText(f"當前端口: {self.selected_hub_port}")
        self.refresh_hub_table()

    def apply_hub_config(self):
        if not self.selected_hub_port: return
        port = self.selected_hub_port
        interfaces = self.port_config.get(port, [])
        proxy_core.route_manager.update_port_binding(port, interfaces)
        success = proxy_core.server_controller.start_port(port)
        self.update_hub_list_item(port, success)
        if success:
            self.sync_hub_proxy(port)
            logging.info(f"Hub 端口 {port} 已啟動")

    def sync_hub_proxy(self, port):
        if port in self.hub_proxy_map: return
        pid = self.bridge.add_proxy("127.0.0.1", port, "", "", ProxyType.SOCKS5, f"Hub_Port_{port}")
        if pid > 0:
            self.hub_proxy_map[port] = pid
            self.refresh_proxy_combobox()

    def update_hub_list_item(self, port, is_running):
        for i in range(self.list_hub_ports.count()):
            item = self.list_hub_ports.item(i)
            if item.text().startswith(str(port)):
                status = "(運行中)" if is_running else "(失敗)"
                item.setText(f"{port} {status}")
                item.setForeground(QBrush(QColor("green") if is_running else QColor("red")))
                break

    def refresh_hub_table(self):
        scroll_pos = self.table_hub.verticalScrollBar().value()
        self.table_hub.setRowCount(0)
        if not self.selected_hub_port: return
        filter_keyword = self.txt_hub_filter.text().lower().strip()
        bound_list = self.port_config.get(self.selected_hub_port, [])
        all_interface_names = set(self.current_interfaces.keys()) | set(bound_list)
        sorted_names = sorted(list(all_interface_names),
                              key=lambda x: (0 if x in self.current_interfaces else 1, x))

        for name in sorted_names:
            if filter_keyword and filter_keyword not in name.lower(): continue
            row = self.table_hub.rowCount()
            self.table_hub.insertRow(row)
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Checked if name in bound_list else Qt.CheckState.Unchecked)
            self.table_hub.setItem(row, 0, chk)
            name_item = QTableWidgetItem(name)
            self.table_hub.setItem(row, 1, name_item)
            if name in self.current_interfaces:
                data = self.current_interfaces[name]
                self.table_hub.setItem(row, 2, QTableWidgetItem(data['ipv4']))
                lat_item = QTableWidgetItem(str(data['latency']) + " ms")
                if data['latency'] < 100: lat_item.setForeground(QBrush(QColor("#4CAF50")))
                elif data['latency'] < 300: lat_item.setForeground(QBrush(QColor("#FF9800")))
                else: lat_item.setForeground(QBrush(QColor("#F44336")))
                self.table_hub.setItem(row, 3, lat_item)
                active = proxy_core.route_manager.interfaces.get(name, {}).get('active_conns', 0)
                self.table_hub.setItem(row, 4, QTableWidgetItem(str(active)))
            else:
                name_item.setForeground(QBrush(QColor("gray")))
                offline_item = QTableWidgetItem("離線 (等待重連...)")
                offline_item.setForeground(QBrush(QColor("gray")))
                self.table_hub.setItem(row, 2, offline_item)
                self.table_hub.setItem(row, 3, QTableWidgetItem("-"))
                self.table_hub.setItem(row, 4, QTableWidgetItem("0"))
        self.table_hub.verticalScrollBar().setValue(scroll_pos)

    def on_hub_select_all_visible(self):
        if not self.selected_hub_port: return
        current_bound = self.port_config.get(self.selected_hub_port, [])
        is_changed = False
        for row in range(self.table_hub.rowCount()):
            name_item = self.table_hub.item(row, 1)
            if not name_item: continue
            name = name_item.text()
            chk_item = self.table_hub.item(row, 0)
            if chk_item.checkState() != Qt.CheckState.Checked:
                chk_item.setCheckState(Qt.CheckState.Checked)
                if name not in current_bound:
                    current_bound.append(name)
                    is_changed = True
        if is_changed:
            self.port_config[self.selected_hub_port] = current_bound
            proxy_core.route_manager.update_port_binding(self.selected_hub_port, current_bound)
            self.append_log(f"已批次更新端口 {self.selected_hub_port} 的綁定介面")

    def on_hub_table_click(self, row, col):
        if col == 0 and self.selected_hub_port:
            name = self.table_hub.item(row, 1).text()
            item = self.table_hub.item(row, 0)
            checked = (item.checkState() == Qt.CheckState.Checked)
            curr = self.port_config.get(self.selected_hub_port, [])
            if checked and name not in curr: curr.append(name)
            elif not checked and name in curr: curr.remove(name)
            self.port_config[self.selected_hub_port] = curr
            proxy_core.route_manager.update_port_binding(self.selected_hub_port, curr)

    def refresh_proxy_combobox(self):
        current_data = self.combo_proxy.currentData()
        self.combo_proxy.clear()
        has_real_proxies = False
        sorted_hubs = sorted(self.hub_proxy_map.items())
        for port, pid in sorted_hubs:
            self.combo_proxy.addItem(f"[Hub] Local Port {port}", pid)
            has_real_proxies = True
        for p in self.custom_proxies:
            self.combo_proxy.addItem(f"[Custom] {p['name']}", p['id'])
            has_real_proxies = True
        if not has_real_proxies:
            self.combo_proxy.addItem("未指定 (Fallback to Direct)", 0)
        idx = self.combo_proxy.findData(current_data)
        if idx >= 0: self.combo_proxy.setCurrentIndex(idx)
        elif self.combo_proxy.count() > 0: self.combo_proxy.setCurrentIndex(0)

    def on_rule_double_click(self, row, col):
        if row < 0: return
        rule_id = int(self.table_rules.item(row, 0).text())
        rule_data = next((r for r in self.rules if r['id'] == rule_id), None)
        if not rule_data: return

        self.editing_rule_id = rule_id
        self.group_rule_form.setTitle(f"編輯規則 (ID: {rule_id})")
        self.btn_rule_action.setText("保存修改")
        self.btn_rule_action.setStyleSheet("background-color: #FF9800; color: white; font-weight: bold;")
        self.btn_rule_cancel.show()

        self.ent_target.setText(rule_data['target'])
        self.ent_hosts.setText(rule_data.get('hosts', '*'))
        self.ent_ports.setText(rule_data.get('ports', '*'))
        if rule_data['type'] == 'PID': self.rb_pid.setChecked(True)
        else: self.rb_name.setChecked(True)
        idx_proto = self.combo_proto.findText(rule_data.get('proto', 'BOTH'))
        if idx_proto >= 0: self.combo_proto.setCurrentIndex(idx_proto)
        idx_action = self.combo_action.findText(rule_data['action'])
        if idx_action >= 0: self.combo_action.setCurrentIndex(idx_action)
        current_proxy_text = rule_data['proxy']
        idx_proxy = self.combo_proxy.findText(current_proxy_text)
        if idx_proxy >= 0: self.combo_proxy.setCurrentIndex(idx_proxy)
        else: self.combo_proxy.setCurrentIndex(0)

    def cancel_rule_edit(self):
        self.editing_rule_id = None
        self.group_rule_form.setTitle("新增攔截規則")
        self.btn_rule_action.setText("新增規則")
        self.btn_rule_action.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        self.btn_rule_cancel.hide()
        self.ent_target.clear()
        self.ent_hosts.setText("*")
        self.ent_ports.setText("*")
        self.combo_proxy.setCurrentIndex(0)
        self.combo_action.setCurrentIndex(0)

    def save_rule_action(self):
        target = self.ent_target.text().strip()
        if not target: return
        hosts = self.ent_hosts.text().strip() or "*"
        ports = self.ent_ports.text().strip() or "*"
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

        if self.editing_rule_id is not None:
            if hasattr(self.bridge.lib, 'NetRedirector_DeleteRule'):
                 self.bridge.lib.NetRedirector_DeleteRule(self.editing_rule_id)
            self.rules = [r for r in self.rules if r['id'] != self.editing_rule_id]
            logging.info(f"正在更新規則 ID {self.editing_rule_id} -> 先行刪除")

        rid = 0
        if is_pid:
            if not target.isdigit():
                QMessageBox.warning(self, "錯誤", "PID 需為數字")
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
            self.rules.append({
                'id': rid,
                'type': 'PID' if is_pid else 'Name',
                'target': target,
                'hosts': hosts,
                'ports': ports,
                'proto': proto_str,
                'action': action_text,
                'proxy': proxy_text
            })
            self.refresh_rules_table()
            self.cancel_rule_edit()
            self.append_log(f"規則已{'更新' if self.editing_rule_id else '新增'} (ID: {rid})")
        else:
            QMessageBox.warning(self, "失敗", "驅動返回錯誤，規則添加失敗。")

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
            self.table_rules.setItem(row, 6, QTableWidgetItem(r['action']))
            self.table_rules.setItem(row, 7, QTableWidgetItem(r['proxy']))

    def save_custom_proxy(self):
        name = self.ent_cp_name.text()
        ip = self.ent_cp_ip.text()
        port_str = self.ent_cp_port.text()
        user = self.ent_cp_user.text()
        pwd = self.ent_cp_pass.text()
        ptype_str = self.combo_cp_type.currentText()
        if not name or not ip or not port_str:
            QMessageBox.warning(self, "警告", "名稱、IP 與 Port 為必填")
            return
        try: port = int(port_str)
        except: return
        ptype = ProxyType.SOCKS5 if ptype_str == "SOCKS5" else ProxyType.HTTP

        # [根因修正] 編輯代理「原地更新」：EditProxyConfig 保留相同 proxy ID，
        # 已建立的規則仍指向同一 ID，新帳密立即對所有規則生效，不需重刷規則
        old_proxy_id = self.editing_proxy_id
        if old_proxy_id is not None:
            edit_fn = getattr(self.bridge.lib, 'NetRedirector_EditProxyConfig', None)
            if edit_fn is not None:
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
                            p.update({'name': name, 'type': ptype_str, 'ip': ip, 'port': port, 'user': user, 'pass': pwd})
                    self.refresh_custom_proxy_table()
                    self.refresh_proxy_combobox()
                    self.cancel_proxy_edit()
                    self.append_log(f"自訂代理已更新 (ID 不變，立即生效): {name}")
                    return
                else:
                    QMessageBox.warning(self, "失敗", "DLL 無法更新代理配置")
                    return

            # 舊版 DLL 沒有 EditProxyConfig 的 fallback：刪除+重建（ID 會變，需重刷規則）
            if hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
                self.bridge.lib.NetRedirector_DeleteProxyConfig(old_proxy_id)
            self.custom_proxies = [p for p in self.custom_proxies if p['id'] != old_proxy_id]

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
            self.cancel_proxy_edit()
            self.append_log(f"自訂代理已新增: {name}")
            # 只有 fallback 刪除+重建路徑才需要重刷引用舊 ID 的規則
            if old_proxy_id is not None and pid != old_proxy_id:
                self.append_log(f"代理 ID 已變更 ({old_proxy_id} -> {pid})，重刷引用該代理的規則...")
                self.reapply_all_rules(only_proxy_id=old_proxy_id)
        else:
            QMessageBox.warning(self, "失敗", "DLL 無法添加代理配置")

    def test_all_proxies(self):
        self.append_log("開始測試所有自訂代理 (目標: api.ipify.org)...")
        import threading
        import traceback
        def worker_func():
            try:
                for p in self.custom_proxies:
                    try:
                        success, ms, result = check_proxy_connection(p)
                        if success:
                            p['latency'] = f"{ms}ms (IP: {result})"
                            p['status_color'] = "green" if ms < 500 else "orange"
                            self.redir_signals.log_received.emit(f"測試成功: {p['name']} -> {result}")
                        else:
                            err_msg = str(result)
                            if "timed out" in err_msg: err_msg = "超時"
                            elif "refused" in err_msg: err_msg = "連線被拒"
                            p['latency'] = f"失敗: {err_msg}"
                            p['status_color'] = "red"
                    except Exception as e_inner:
                        p['latency'] = f"錯誤: {str(e_inner)}"
                        p['status_color'] = "red"
                    self.update_proxy_table_signal.emit()
                    time.sleep(0.05) 
                self.redir_signals.log_received.emit(f"所有代理測試完成。")
            except Exception as e:
                err_trace = traceback.format_exc()
                self.redir_signals.log_received.emit(f"測試線程嚴重崩潰:\n{err_trace}")
        t = threading.Thread(target=worker_func, daemon=True)
        t.start()

    def del_custom_proxy(self):
        row = self.table_custom_proxies.currentRow()
        if row < 0: return
        pid = int(self.table_custom_proxies.item(row, 0).text())
        if hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
            self.bridge.lib.NetRedirector_DeleteProxyConfig(pid)
        self.custom_proxies = [p for p in self.custom_proxies if p['id'] != pid]
        self.refresh_custom_proxy_table()
        self.refresh_proxy_combobox()
        # [修正] 代理被刪除後，引用它的規則若不重刷會殘留失效的 proxy ID
        self.reapply_all_rules(only_proxy_id=pid)

    def on_proxy_double_click(self, row, col):
        if row < 0: return
        pid = int(self.table_custom_proxies.item(row, 0).text())
        proxy_data = next((p for p in self.custom_proxies if p['id'] == pid), None)
        if not proxy_data: return
        self.editing_proxy_id = pid
        self.group_proxy_form.setTitle(f"編輯代理 (ID: {pid})")
        self.btn_proxy_save.setText("保存修改")
        self.btn_proxy_save.setStyleSheet("background-color: #FF9800; color: white;")
        self.btn_proxy_cancel.show()
        self.ent_cp_name.setText(proxy_data['name'])
        idx = self.combo_cp_type.findText(proxy_data['type'])
        if idx >= 0: self.combo_cp_type.setCurrentIndex(idx)
        self.ent_cp_ip.setText(proxy_data['ip'])
        self.ent_cp_port.setText(str(proxy_data['port']))
        self.ent_cp_user.setText(proxy_data.get('user', ''))
        self.ent_cp_pass.setText(proxy_data.get('pass', ''))

    def cancel_proxy_edit(self):
        self.editing_proxy_id = None
        self.group_proxy_form.setTitle("新增外部代理 (SOCKS5/HTTP)")
        self.btn_proxy_save.setText("新增代理")
        self.btn_proxy_save.setStyleSheet("background-color: #2196F3; color: white;")
        self.btn_proxy_cancel.hide()
        self.ent_cp_name.clear()
        self.ent_cp_ip.clear()
        self.ent_cp_port.clear()
        self.ent_cp_user.clear()
        self.ent_cp_pass.clear()

    def refresh_custom_proxy_table(self):
        scroll = self.table_custom_proxies.verticalScrollBar().value()
        self.table_custom_proxies.setRowCount(0)
        for p in self.custom_proxies:
            row = self.table_custom_proxies.rowCount()
            self.table_custom_proxies.insertRow(row)
            self.table_custom_proxies.setItem(row, 0, QTableWidgetItem(str(p['id'])))
            self.table_custom_proxies.setItem(row, 1, QTableWidgetItem(p['name']))
            self.table_custom_proxies.setItem(row, 2, QTableWidgetItem(p['type']))
            self.table_custom_proxies.setItem(row, 3, QTableWidgetItem(f"{p['ip']}:{p['port']}"))
            auth = "Yes" if p['user'] else "No"
            self.table_custom_proxies.setItem(row, 4, QTableWidgetItem(auth))
            lat_str = str(p.get('latency', '-'))
            lat_item = QTableWidgetItem(lat_str)
            color_code = p.get('status_color', '')
            if color_code == "green":
                lat_item.setForeground(QBrush(QColor("#4CAF50")))
                lat_item.setToolTip(f"測試成功，出口 IP: {lat_str.split('IP:')[-1].strip(')')}")
            elif color_code == "orange":
                lat_item.setForeground(QBrush(QColor("#FF9800")))
            elif color_code == "red":
                lat_item.setForeground(QBrush(QColor("#F44336")))
                lat_item.setToolTip(lat_str)
            else:
                lat_item.setForeground(QBrush(QColor("gray")))
            self.table_custom_proxies.setItem(row, 5, lat_item)
        self.table_custom_proxies.verticalScrollBar().setValue(scroll)
        self.table_custom_proxies.resizeColumnToContents(5)

    def show_traffic_menu(self, pos):
        item = self.tree_traffic.itemAt(pos)
        if not item: return
        row = item.row()
        pid = self.tree_traffic.item(row, 2).text()
        proc = self.tree_traffic.item(row, 1).text()
        menu = QMenu()
        act_pid = QAction(f"為 PID {pid} 新增規則", self)
        act_pid.triggered.connect(lambda: self.quick_add_rule(pid, True))
        act_proc = QAction(f"為 {proc} 新增規則", self)
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
            
            action_idx = 0
            if "DIRECT" in r['action']: action_idx = 1
            elif "BLOCK" in r['action']: action_idx = 2
            
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
                self.btn_master_switch.setText("停止攔截服務 (Stop)")
                self.btn_master_switch.setStyleSheet("background-color: #4CAF50; color: white;")
                self.lbl_status.setText("狀態: 運行中")
                self.lbl_status.setStyleSheet("color: green; font-weight: bold;")
                logging.info("NetRedirector Started")
                
                # [關鍵修正] 啟動成功後，立即重刷所有規則
                # 這會強制 DLL 重新產生 WinDivert Filter String
                self.reapply_all_rules()
                
            else:
                # 啟動失敗，將按鈕彈回
                self.btn_master_switch.setChecked(False)
                QMessageBox.critical(self, "錯誤", "無法啟動驅動，請確認管理員權限或驅動檔案是否存在。")
        else:
            # === 停止服務 ===
            self.bridge.stop()
            self.is_redirector_running = False
            self.btn_master_switch.setText("啟動攔截服務 (Start)")
            self.btn_master_switch.setStyleSheet("background-color: #f44336; color: white;")
            self.lbl_status.setText("狀態: 停止")
            self.lbl_status.setStyleSheet("color: red;")
            logging.info("NetRedirector Stopped")

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
        QMessageBox.warning(None, "權限不足", "請以管理員身分執行！")
        sys.exit(1)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())