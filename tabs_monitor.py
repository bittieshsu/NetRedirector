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
                             QTabWidget, QComboBox, QLineEdit, QRadioButton, QButtonGroup, QMenu,
                             QFrame, QCheckBox, QAbstractItemView)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QColor, QBrush, QAction

from i18n import i18n as tr, SUPPORTED_LANGS
import network_utils
import proxy_core
import secure_config
import rule_utils
import ui_theme  # [即時監控] 深色主題徽章 / 顏色常數
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol


class MonitorTabMixin:
    MONITOR_ROW_CAP = 500              # 監控緩衝上限 (與原行為一致)
    MONITOR_SCROLL_INTERVAL_MS = 250   # 自動捲動節流 (4 Hz)
    MONITOR_INFO_COL = 4               # 資訊 (徽章) 欄
    MONITOR_INFO_COL_WIDTH = 140       # 初始寬度；實際由 _fit_info_column 依徽章調整
    # 分段篩選：索引對應的類別 (None = 全部)
    _MONITOR_FILTERS = [None, "Proxy", "Direct", "Blocked"]
    _MONITOR_FILTER_LABELS = ["全部", "Proxy", "Direct", "Blocked"]
    # DLL 送出的 info 開頭 -> 徽章顏色
    _MONITOR_RESULT_COLORS = {
        "Proxy": ui_theme.COLOR_ACCENT,
        "Direct": ui_theme.COLOR_SUCCESS,
        "Blocked": ui_theme.COLOR_DANGER,
    }

    def setup_monitor_tab(self):
        page_layout = QVBoxLayout(self.tab_monitor)
        page_layout.setContentsMargins(12, 12, 12, 12)
        page_layout.setSpacing(10)

        # ---------- 頁首 ----------
        header = QWidget()
        header_lay = QHBoxLayout(header)
        header_lay.setContentsMargins(0, 0, 0, 0)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        self.lbl_traffic_desc = QLabel("")
        self.lbl_traffic_desc.setObjectName("PageDesc")
        self._reg("text", self.lbl_traffic_desc,
                  "即時觀察每個連線的處理結果；對任一行按右鍵可快速建立規則。")
        title_col.addWidget(self.lbl_traffic_desc)
        header_lay.addLayout(title_col)
        header_lay.addStretch()

        btn_clear = QPushButton("")
        btn_clear.setObjectName("GhostBtn")
        self._reg("text", btn_clear, "清除記錄")
        btn_clear.clicked.connect(self.clear_traffic)
        header_lay.addWidget(btn_clear)
        page_layout.addWidget(header)

        # ---------- 工具列：分段篩選 + 搜尋 + 跟隨最新 + 暫停 ----------
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        seg = QFrame()
        seg.setObjectName("Seg")
        seg_lay = QHBoxLayout(seg)
        seg_lay.setContentsMargins(3, 3, 3, 3)
        seg_lay.setSpacing(2)
        self._traffic_filter_group = QButtonGroup(seg)
        self._traffic_filter_group.setExclusive(True)
        for idx, label in enumerate(self._MONITOR_FILTER_LABELS):
            item = QPushButton("")
            item.setObjectName("SegItem")
            item.setCheckable(True)
            item.setChecked(idx == 0)
            item.setCursor(Qt.CursorShape.PointingHandCursor)
            self._reg("text", item, label)
            self._traffic_filter_group.addButton(item, idx)
            seg_lay.addWidget(item)
        self._traffic_filter_group.idClicked.connect(
            lambda idx: self.set_traffic_filter(self._MONITOR_FILTERS[idx]))
        toolbar.addWidget(seg)

        self.ent_traffic_search = QLineEdit()
        self.ent_traffic_search.setFixedWidth(240)
        self._reg("placeholder", self.ent_traffic_search, "🔍 篩選進程名稱或目標 IP")
        self.ent_traffic_search.textChanged.connect(self.apply_traffic_filters)
        toolbar.addWidget(self.ent_traffic_search)

        toolbar.addStretch()

        self.chk_traffic_follow = QCheckBox("")
        self.chk_traffic_follow.setChecked(True)
        self.chk_traffic_follow.setCursor(Qt.CursorShape.PointingHandCursor)
        self._reg("text", self.chk_traffic_follow, "跟隨最新")
        toolbar.addWidget(self.chk_traffic_follow)

        self.btn_traffic_pause = QPushButton("")
        self.btn_traffic_pause.setObjectName("GhostBtn")
        self.btn_traffic_pause.setCheckable(True)
        self.btn_traffic_pause.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_traffic_pause.toggled.connect(self.toggle_traffic_pause)
        toolbar.addWidget(self.btn_traffic_pause)
        page_layout.addLayout(toolbar)

        # ---------- 表格卡片 ----------
        card = QFrame()
        card.setObjectName("Card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(10, 10, 10, 10)
        card_lay.setSpacing(6)

        cols = ["Time", "Process", "PID", "Destination", "Info"]
        self.tree_traffic = QTableWidget()
        self.tree_traffic.setColumnCount(len(cols))
        self._reg("headers", self.tree_traffic, cols)   # [i18n] 表頭也走語系檔
        self.tree_traffic.verticalHeader().setVisible(False)
        # 38px：徽章本身約 23px，儲存格 QSS padding 上下各 6px 會再吃掉 12px，
        # 32px 會讓徽章底部被裁掉。
        self.tree_traffic.verticalHeader().setDefaultSectionSize(38)
        self.tree_traffic.setShowGrid(False)
        self.tree_traffic.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        # 短欄位依內容自動收合，Process(變動文字)才伸展。
        # Info 欄放的是徽章 cell widget：ResizeToContents 量到的是徽章寬度，
        # 不含儲存格左右各 10px 的 QSS padding，會把徽章右側裁掉；因此改用
        # Interactive，由 _fit_info_column 依徽章實際需求設定欄寬。
        for col, mode in (
                (0, QHeaderView.ResizeMode.ResizeToContents),
                (1, QHeaderView.ResizeMode.Stretch),
                (2, QHeaderView.ResizeMode.ResizeToContents),
                (3, QHeaderView.ResizeMode.ResizeToContents),
                (self.MONITOR_INFO_COL, QHeaderView.ResizeMode.Interactive)):
            self.tree_traffic.horizontalHeader().setSectionResizeMode(col, mode)
        self.tree_traffic.setColumnWidth(
            self.MONITOR_INFO_COL, self.MONITOR_INFO_COL_WIDTH)
        self.tree_traffic.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tree_traffic.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_traffic.customContextMenuRequested.connect(self.show_traffic_menu)
        # 使用者手動捲動 (滾輪/拖曳) 時自動取消跟隨；程式呼叫 scrollToBottom
        # 走的是 setValue，不會觸發 actionTriggered，所以不會誤判。
        self.tree_traffic.verticalScrollBar().actionTriggered.connect(
            lambda _action: self.chk_traffic_follow.setChecked(False))
        card_lay.addWidget(self.tree_traffic, 1)
        page_layout.addWidget(card, 1)

        # ---------- 狀態列：即時計數 ----------
        status = QWidget()
        status_lay = QHBoxLayout(status)
        status_lay.setContentsMargins(2, 0, 2, 0)
        status_lay.setSpacing(8)
        self.lbl_traffic_buffer = QLabel("")
        ui_theme.style_badge(self.lbl_traffic_buffer, ui_theme.COLOR_TEXT_DIM)
        self.lbl_traffic_proxy = QLabel("Proxy 0")
        ui_theme.style_badge(self.lbl_traffic_proxy, ui_theme.COLOR_ACCENT)
        self.lbl_traffic_direct = QLabel("Direct 0")
        ui_theme.style_badge(self.lbl_traffic_direct, ui_theme.COLOR_SUCCESS)
        self.lbl_traffic_block = QLabel("Blocked 0")
        ui_theme.style_badge(self.lbl_traffic_block, ui_theme.COLOR_DANGER)
        for badge_lbl in (self.lbl_traffic_buffer, self.lbl_traffic_proxy,
                          self.lbl_traffic_direct, self.lbl_traffic_block):
            status_lay.addWidget(badge_lbl)
        status_lay.addStretch()
        page_layout.addWidget(status)

        # ---------- 狀態 ----------
        self._traffic_counts = {"Proxy": 0, "Direct": 0, "Blocked": 0}
        self._traffic_filter = None
        self._traffic_paused = False
        self._sync_traffic_pause_text()
        self._refresh_traffic_counters()

        # 節流自動捲動 (4 Hz)。不逐列 scrollToBottom()：BT 高併發下那是整個
        # UI 最貴的一行，改由此計時器批次捲動。
        self._traffic_scroll_timer = QTimer(self)
        self._traffic_scroll_timer.setInterval(self.MONITOR_SCROLL_INTERVAL_MS)
        self._traffic_scroll_timer.timeout.connect(self._flush_traffic_scroll)
        self._traffic_scroll_timer.start()

    # =====================================================================
    # 即時流量：列插入 / 篩選 / 捲動 / 計數
    # =====================================================================
    def append_traffic_row(self, process, pid, ip, port, info):
        """由 DLL 連線回呼 (經訊號) 呼叫，對應原本的 on_traffic_event。

        效能注意：保留 500 筆上限，超出時移除最舊一列；且不在這裡逐列
        scrollToBottom()，改由節流計時器批次捲動。
        """
        if self._traffic_paused:
            return

        removed = False
        if self.tree_traffic.rowCount() >= self.MONITOR_ROW_CAP:
            self.tree_traffic.removeRow(0)
            removed = True

        row = self.tree_traffic.rowCount()
        self.tree_traffic.insertRow(row)

        category = info.split(" ", 1)[0]

        ts_item = QTableWidgetItem(datetime.now().strftime("%H:%M:%S"))
        # 篩選靠這個 UserRole：結果欄是徽章 widget，讀不到文字
        ts_item.setData(Qt.ItemDataRole.UserRole, category)
        self.tree_traffic.setItem(row, 0, ts_item)
        self.tree_traffic.setItem(row, 1, QTableWidgetItem(process))
        self.tree_traffic.setItem(row, 2, QTableWidgetItem(str(pid)))
        self.tree_traffic.setItem(row, 3, QTableWidgetItem(f"{ip}:{port}"))

        result_lbl = QLabel(info)
        ui_theme.style_badge(
            result_lbl,
            self._MONITOR_RESULT_COLORS.get(category, ui_theme.COLOR_TEXT_DIM))
        holder = QWidget()
        holder.setObjectName("CellWrap")
        holder_lay = QHBoxLayout(holder)
        holder_lay.setContentsMargins(0, 0, 0, 0)
        # 垂直置中：徽章不會被拉長到列高，底部就不會被裁切
        holder_lay.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        holder_lay.addWidget(result_lbl)
        self.tree_traffic.setCellWidget(row, self.MONITOR_INFO_COL, holder)
        self._fit_info_column(result_lbl)

        self._traffic_counts[category] = self._traffic_counts.get(category, 0) + 1

        if removed:
            # removeRow 會位移列索引，隱藏狀態必須重算才不會錯位
            self.apply_traffic_filters()
        else:
            self.tree_traffic.setRowHidden(row, not self._traffic_row_matches(row))

        self._refresh_traffic_counters()

    def _fit_info_column(self, badge):
        """把資訊欄加寬到能完整顯示徽章。

        徽章是塞進儲存格的 widget，會被 QSS 的 item 內距左右各內縮
        TABLE_ITEM_PADDING_H，因此欄寬要在徽章本身寬度之外再加回這層內距，
        否則文字右側 (例如 "Direct (TCP)") 會被裁掉。只加寬、不縮窄，
        所以語言或字型變動時也不會來回跳動。
        """
        needed = (badge.sizeHint().width()
                  + ui_theme.TABLE_ITEM_PADDING_H * 2 + 4)
        if needed > self.tree_traffic.columnWidth(self.MONITOR_INFO_COL):
            self.tree_traffic.setColumnWidth(self.MONITOR_INFO_COL, needed)

    def set_traffic_filter(self, category):
        """category 為 None(全部) 或 'Proxy' / 'Direct' / 'Blocked'。"""
        self._traffic_filter = category
        self.apply_traffic_filters()

    def _traffic_row_matches(self, row):
        cat_item = self.tree_traffic.item(row, 0)
        row_cat = cat_item.data(Qt.ItemDataRole.UserRole) if cat_item else ""

        if self._traffic_filter and row_cat != self._traffic_filter:
            return False

        text = self.ent_traffic_search.text().strip().lower()
        if not text:
            return True
        proc_item = self.tree_traffic.item(row, 1)
        dest_item = self.tree_traffic.item(row, 3)
        proc = proc_item.text().lower() if proc_item else ""
        dest = dest_item.text().lower() if dest_item else ""
        return text in proc or text in dest

    def apply_traffic_filters(self):
        for row in range(self.tree_traffic.rowCount()):
            self.tree_traffic.setRowHidden(row, not self._traffic_row_matches(row))

    def _flush_traffic_scroll(self):
        if not self.chk_traffic_follow.isChecked():
            return
        if not self.tree_traffic.isVisible():
            return  # 分頁不在前景，不需要捲動
        scrollbar = self.tree_traffic.verticalScrollBar()
        if scrollbar.value() >= scrollbar.maximum() - 4:
            self.tree_traffic.scrollToBottom()

    def toggle_traffic_pause(self, paused):
        """暫停時不再插入新列，讓使用者能停下來檢視目前內容。"""
        self._traffic_paused = paused
        self._sync_traffic_pause_text()

    def _sync_traffic_pause_text(self):
        self.btn_traffic_pause.setText(
            self.t("繼續" if self._traffic_paused else "暫停"))

    def clear_traffic(self):
        self.tree_traffic.setRowCount(0)
        self._traffic_counts = {"Proxy": 0, "Direct": 0, "Blocked": 0}
        self._refresh_traffic_counters()

    def _refresh_traffic_counters(self):
        self.lbl_traffic_buffer.setText(
            self.t("緩衝 {n} 筆").format(n=self.tree_traffic.rowCount()))
        self.lbl_traffic_proxy.setText(f"Proxy {self._traffic_counts['Proxy']}")
        self.lbl_traffic_direct.setText(f"Direct {self._traffic_counts['Direct']}")
        self.lbl_traffic_block.setText(f"Blocked {self._traffic_counts['Blocked']}")

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
        # 結果欄現在是徽章 widget，itemAt() 在該欄會回 None；改用 rowAt()
        # 才不會右鍵點在徽章上就沒反應。
        row = self.tree_traffic.rowAt(pos.y())
        if row < 0:
            return
        pid_item = self.tree_traffic.item(row, 2)
        proc_item = self.tree_traffic.item(row, 1)
        if not pid_item or not proc_item:
            return
        self.tree_traffic.selectRow(row)
        pid = pid_item.text()
        proc = proc_item.text()
        menu = QMenu()
        act_pid = QAction(self.t("為 PID {pid} 新增規則").format(pid=pid), self)
        act_pid.triggered.connect(lambda: self.quick_add_rule(pid, True))
        act_proc = QAction(self.t("為 {proc} 新增規則").format(proc=proc), self)
        act_proc.triggered.connect(lambda: self.quick_add_rule(proc, False))
        menu.addAction(act_pid)
        menu.addAction(act_proc)
        menu.exec(self.tree_traffic.viewport().mapToGlobal(pos))

    def quick_add_rule(self, target, is_pid):
        # 規則表單已改為彈出式對話框：切到規則分頁後直接開對話框並帶入目標
        self.tabs.setCurrentIndex(1)
        self.open_add_rule_dialog(default_target=str(target), default_is_pid=is_pid)

# [新增] 強制重刷規則到 DLL (解決啟動後規則不生效的問題)
    def _resolve_proxy(self, rule):
        """把規則的代理參照解析成 (proxy_id, 顯示文字)。

        優先用穩定識別 proxy_name ("custom:名稱" / "hub:端口", 新格式;
        舊版無前綴值向下相容 — custom 先、hub 後);再退回比對顯示字串。
        代理已被刪除時回傳 (0, 原字串), 讓呼叫端決定後續 (直連/轉換)。
        """
        proxy_name = rule.get('proxy_name', '')
        if proxy_name:
            if proxy_name.startswith('custom:'):
                want = proxy_name[7:]
                for p in self.custom_proxies:
                    if p['name'] == want:
                        return p['id'], f"[Custom] {p['name']}"
            elif proxy_name.startswith('hub:'):
                want = proxy_name[4:]
                for port, pid in self.hub_proxy_map.items():
                    if str(port) == want:
                        return pid, f"[Hub] Local Port {port}"
            else:
                # 舊版無前綴: 沿用舊行為 (custom 名稱先比, 再比 hub 端口)
                for p in self.custom_proxies:
                    if p['name'] == proxy_name:
                        return p['id'], f"[Custom] {p['name']}"
                for port, pid in self.hub_proxy_map.items():
                    if str(port) == proxy_name:
                        return pid, f"[Hub] Local Port {port}"
        proxy_text = rule.get('proxy', '')
        for text, proxy_id in self.proxy_choices():
            if text == proxy_text:
                return int(proxy_id or 0), proxy_text
        return 0, proxy_text

    def _rule_proxy_id(self, rule):
        """規則引用的代理 ID。

        快路徑: 記錄的最後已知 proxy_id 仍然有效 (該代理存在且 ID 相同)
        就直接用 — 特別是「代理已刪除」情境, 名稱解析已落空, 但重刷邏輯
        需要靠這個舊 ID 找出受影響的規則。
        """
        last = rule.get('proxy_id')
        if last:
            for p in self.custom_proxies:
                if p['id'] == last:
                    return last
            for _port, pid in self.hub_proxy_map.items():
                if pid == last:
                    return last
        return self._resolve_proxy(rule)[0]

    def reapply_all_rules(self, only_proxy_id=None):
        if not self.rules:
            return

        # 若指定 only_proxy_id，只重刷引用該代理的規則（例如刪除代理後；
        # 此時名稱解析已失效, 靠 rule 內記錄的最後已知 proxy_id 找出目標）
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
            if not r.get('enabled', True):
                # 停用中的規則不進 DLL；保留資料與停用狀態
                refreshed_rules.append(r)
                continue

            old_id = r['id']

            # 1. 先嘗試刪除舊的 (如果存在) 
            # 注意：如果 DLL 在 Start 時清空了內部列表，這步可能無效但無害
            self.bridge.delete_rule(old_id)

            # 2. 重新解析 Proxy ID (ID 可能在重啟/代理重刷後變更)
            proxy_id, _display = self._resolve_proxy(r)

            # [Fixed] 引用的代理已不存在: 核心對「PROXY 動作 + proxy_id=0」
            # 的行為是直接斷線 (黑洞), 因此把規則轉為直連並明確告知,
            # 而不是讓它指向失效 ID 或以 PROXY+0 重灌
            if proxy_id == 0 and r.get('proxy_id') and self._rule_action_idx(r) == 0:
                r['action_key'] = 1
                r['action'] = 'DIRECT (直連)'
                r['proxy_name'] = ''
                r['proxy'] = self.t("未指定 (Fallback to Direct)")
                self.append_log(f"規則 '{r['target']}' 引用的代理已不存在，已轉為直連")

            r['proxy_id'] = proxy_id

            # 3. 呼叫 DLL 加入規則 (統一入口,這會觸發 UpdateFilter)
            new_rid = self.bridge.add_rule_ex(
                r['type'], r['target'], r.get('hosts', '*'), r.get('ports', '*'),
                r.get('proto', 'BOTH'), self._rule_action_idx(r), int(proxy_id))

            # 4. 更新規則資料中的 ID
            if new_rid > 0:
                r['id'] = new_rid
                refreshed_rules.append(r)
                logging.debug(f"規則 '{r['target']}' 已重刷，新 ID: {new_rid}")
            else:
                self.append_log(f"[錯誤] 無法重刷規則: {r['target']}")
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

