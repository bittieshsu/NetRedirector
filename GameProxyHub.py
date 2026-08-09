import sys
import time
import logging
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTableWidget, QTableWidgetItem, 
                             QPushButton, QLabel, QGroupBox, QSpinBox, QTextEdit, 
                             QListWidget, QSplitter, QMessageBox, QHeaderView)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QBrush

import network_utils
import proxy_core

# --- 日誌處理 ---
class QTextEditLogger(logging.Handler):
    def __init__(self, widget):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        msg = self.format(record)
        QTimer.singleShot(0, lambda: self.widget.append(msg))

# --- 背景監控線程 ---
class NetworkMonitorWorker(QThread):
    data_updated = Signal(dict) 

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        while self.running:
            interfaces = network_utils.get_system_interfaces()
            # 對每個介面 Ping (簡化版：只Ping已連線的)
            for name, details in interfaces.items():
                if details['connected']:
                    details['latency'] = network_utils.ping_address(details['ipv4'], "8.8.8.8")
                else:
                    details['latency'] = 9999
            
            self.data_updated.emit(interfaces)
            for _ in range(30): # 3秒更新一次
                if not self.running: break
                time.sleep(0.1)

    def stop(self):
        self.running = False
        self.wait()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GameProxy Hub - 多端口多路由版")
        self.resize(1100, 700)
        
        # 資料結構
        # port_config = { port: [allowed_interface_names] }
        self.port_config = {} 
        self.current_interfaces = {} # 保存最新的網路掃描結果
        self.selected_port = None # 當前 UI 選中的端口
        
        self.setup_ui()
        
        # 啟動監控
        self.monitor_thread = NetworkMonitorWorker()
        self.monitor_thread.data_updated.connect(self.on_network_update)
        self.monitor_thread.start()
        
        # 初始化 Log
        log_handler = QTextEditLogger(self.log_area)
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S'))
        logging.getLogger().addHandler(log_handler)
        logging.getLogger().setLevel(logging.INFO)

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # --- 上半部：左右分割 (端口管理 | 介面綁定) ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # [左側] 端口管理區
        left_panel = QGroupBox("1. 監聽端口管理")
        left_layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        self.spin_new_port = QSpinBox()
        self.spin_new_port.setRange(1000, 65535)
        self.spin_new_port.setValue(30678)
        self.btn_add_port = QPushButton("新增端口")
        self.btn_add_port.clicked.connect(self.add_port)
        input_layout.addWidget(self.spin_new_port)
        input_layout.addWidget(self.btn_add_port)
        
        self.list_ports = QListWidget()
        self.list_ports.itemClicked.connect(self.on_port_selected)
        
        self.btn_del_port = QPushButton("刪除選中端口")
        self.btn_del_port.clicked.connect(self.del_port)
        self.btn_del_port.setStyleSheet("background-color: #ffcccc;")
        
        left_layout.addLayout(input_layout)
        left_layout.addWidget(self.list_ports)
        left_layout.addWidget(self.btn_del_port)
        left_panel.setLayout(left_layout)
        
        # [右側] 路由綁定區
        right_panel = QGroupBox("2. 路由綁定 (請先在左側選擇端口)")
        right_layout = QVBoxLayout()
        
        self.lbl_current_port = QLabel("當前設定端口: 未選擇")
        self.lbl_current_port.setStyleSheet("font-weight: bold; color: #2196F3;")
        
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["綁定", "介面名稱", "IP", "延遲", "此IP總負載"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        # 綁定 Checkbox 點擊事件
        self.table.cellClicked.connect(self.on_table_click) 
        
        right_layout.addWidget(self.lbl_current_port)
        right_layout.addWidget(self.table)
        right_panel.setLayout(right_layout)
        
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 2) # 右邊寬一點
        
        main_layout.addWidget(splitter, 7) # 佔 70% 高度
        
        # --- 底部：控制與日誌 ---
        bottom_group = QGroupBox("3. 系統控制與日誌")
        bottom_layout = QVBoxLayout()
        
        btn_layout = QHBoxLayout()
        self.btn_apply = QPushButton("啟動/重啟所有端口服務")
        self.btn_apply.setMinimumHeight(40)
        self.btn_apply.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; font-size: 14px;")
        self.btn_apply.clicked.connect(self.apply_config)
        
        self.btn_stop_all = QPushButton("停止所有")
        self.btn_stop_all.clicked.connect(self.stop_all)
        
        btn_layout.addWidget(self.btn_apply)
        btn_layout.addWidget(self.btn_stop_all)
        
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas;")
        
        bottom_layout.addLayout(btn_layout)
        bottom_layout.addWidget(self.log_area)
        bottom_group.setLayout(bottom_layout)
        
        main_layout.addWidget(bottom_group, 3)

    # --- 邏輯處理 ---
    
    def add_port(self):
        port = self.spin_new_port.value()
        if port in self.port_config:
            QMessageBox.warning(self, "錯誤", "端口已存在")
            return
        
        # 預設不綁定任何介面，需手動勾選
        self.port_config[port] = [] 
        self.list_ports.addItem(f"{port}")
        self.spin_new_port.setValue(port + 1)
        logging.info(f"新增設定: Port {port}")

    def del_port(self):
        item = self.list_ports.currentItem()
        if not item: return
        
        port = int(item.text().split()[0])
        del self.port_config[port]
        self.list_ports.takeItem(self.list_ports.row(item))
        
        # 停止該端口服務
        proxy_core.server_controller.stop_port(port)
        
        self.selected_port = None
        self.lbl_current_port.setText("當前設定端口: 未選擇")
        self.refresh_table()

    def on_port_selected(self, item):
        if not item: return
        # 格式可能是 "30678" 或 "30678 (運行中)"
        port_text = item.text().split()[0]
        self.selected_port = int(port_text)
        self.lbl_current_port.setText(f"當前設定端口: {self.selected_port}")
        self.refresh_table()

    def on_network_update(self, interfaces):
        self.current_interfaces = interfaces
        
        # 同步更新 RouteManager 的物理狀態
        for name, data in interfaces.items():
            proxy_core.route_manager.update_interface_status(
                name, data['ipv4'], data['latency'], data['connected']
            )
            
        self.refresh_table()

    def refresh_table(self):
        """刷新右側介面表，根據 selected_port 顯示勾選狀態"""
        # 暫存當前滾動位置
        scroll_pos = self.table.verticalScrollBar().value()
        
        self.table.setRowCount(0)
        if not self.selected_port:
            return

        # 獲取當前端口已綁定的介面列表
        bound_interfaces = self.port_config.get(self.selected_port, [])

        for name, data in self.current_interfaces.items():
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # Column 0: Checkbox
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            if name in bound_interfaces:
                chk_item.setCheckState(Qt.CheckState.Checked)
            else:
                chk_item.setCheckState(Qt.CheckState.Unchecked)
            self.table.setItem(row, 0, chk_item)
            
            # Column 1-4: Info
            self.table.setItem(row, 1, QTableWidgetItem(name))
            self.table.setItem(row, 2, QTableWidgetItem(data['ipv4']))
            
            lat = data['latency']
            lat_item = QTableWidgetItem(str(lat) if lat < 9000 else "Timeout")
            if lat < 100: lat_item.setForeground(QBrush(QColor("green")))
            elif lat < 300: lat_item.setForeground(QBrush(QColor("orange")))
            else: lat_item.setForeground(QBrush(QColor("red")))
            self.table.setItem(row, 3, lat_item)
            
            # 從 route_manager 獲取實時連線數
            active = 0
            if name in proxy_core.route_manager.interfaces:
                active = proxy_core.route_manager.interfaces[name]['active_conns']
            self.table.setItem(row, 4, QTableWidgetItem(str(active)))

        self.table.verticalScrollBar().setValue(scroll_pos)

    def on_table_click(self, row, col):
        """處理勾選邏輯"""
        if col == 0 and self.selected_port: # 確保點擊的是第一列 (Checkbox) 且有選中端口
            item = self.table.item(row, 0)
            iface_name = self.table.item(row, 1).text()
            
            # 直接讀取點擊後的 CheckState
            is_checked = (item.checkState() == Qt.CheckState.Checked)
            
            # 從 port_config 獲取當前端口的綁定列表
            current_list = self.port_config.get(self.selected_port, [])
            
            if is_checked:
                # 如果被勾選，且不在列表中，則新增
                if iface_name not in current_list:
                    current_list.append(iface_name)
            else:
                # 如果被取消勾選，且在列表中，則移除
                if iface_name in current_list:
                    current_list.remove(iface_name)
            
            # 更新 port_config 中的列表
            self.port_config[self.selected_port] = current_list
            
            # 立即更新核心 RouteManager 的綁定配置
            proxy_core.route_manager.update_port_binding(self.selected_port, current_list)
            
            logging.info(f"Port {self.selected_port} 綁定更新: {current_list}")

    def apply_config(self):
        """啟動所有設定的端口"""
        for port, interfaces in self.port_config.items():
            if not interfaces:
                logging.warning(f"Port {port} 未綁定任何介面，將無法連網")
            
            # 更新綁定資訊
            proxy_core.route_manager.update_port_binding(port, interfaces)
            
            # 啟動服務器
            success = proxy_core.server_controller.start_port(port)
            
            # 更新 UI 列表狀態
            self.update_port_list_visual(port, success)

    def stop_all(self):
        proxy_core.server_controller.stop_all()
        # 重置 UI 文字
        for i in range(self.list_ports.count()):
            item = self.list_ports.item(i)
            txt = item.text().split()[0]
            item.setText(txt)

    def update_port_list_visual(self, port, is_running):
        for i in range(self.list_ports.count()):
            item = self.list_ports.item(i)
            if item.text().startswith(str(port)):
                status = "(運行中)" if is_running else "(失敗)"
                item.setText(f"{port} {status}")
                item.setForeground(QBrush(QColor("green") if is_running else QColor("red")))
                break
                
    def closeEvent(self, event):
        self.monitor_thread.stop()
        proxy_core.server_controller.stop_all()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())