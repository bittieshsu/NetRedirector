# -*- coding: utf-8 -*-
"""ui_theme.py — 現代化深色主題 (自 demo_modern_ui.py 導入正式程式)。

提供:
- MODERN_QSS: 全域深色 QSS (扁平化、圓角、層次感配色)
- build_stylesheet(): 回傳已注入勾選圖示路徑的 QSS
- apply_dark_palette(app): 套用 Fusion + 深色 QPalette，杜絕原生淺色殘留
- 供程式碼取用的顏色常數與徽章/按鈕輔助函式

只設 QSS 不夠：Qt 原生的部分元件 (表格左上角按鈕、捲軸交會角、核取方塊
指示器、彈出選單等) 不受 QSS 覆蓋，會依 QPalette 以「淺色」繪製，在深色
介面上就成為突兀的白塊。因此 QSS 與 QPalette 必須一起套用。
"""

import os
import tempfile

from PySide6.QtGui import QColor, QPalette


# --------------------------------------------------------------- 顏色常數
COLOR_BG = "#12151B"          # 視窗底色
COLOR_PANEL = "#161A22"       # 面板/表格底色
COLOR_ELEVATED = "#1A1F29"    # 頂部列/選單
COLOR_BORDER = "#232B39"
COLOR_TEXT = "#E2E8F0"
COLOR_TEXT_DIM = "#94A3B8"
COLOR_ACCENT = "#38BDF8"      # 主要強調 (藍)
COLOR_SUCCESS = "#34D399"     # 成功/良好 (綠)
COLOR_WARN = "#FBBF24"        # 一般/警告 (黃)
COLOR_DANGER = "#F87171"      # 失敗/封鎖 (紅)


MODERN_QSS = """
QMainWindow, QDialog {
    background-color: #12151B;
}

QWidget {
    color: #E2E8F0;
    font-family: 'Segoe UI', 'Microsoft JhengHei UI', sans-serif;
    font-size: 13px;
}

/* 選單列 */
QMenuBar {
    background-color: #12151B;
    color: #94A3B8;
    padding: 2px 6px;
}
QMenuBar::item {
    padding: 4px 10px;
    border-radius: 4px;
    background: transparent;
}
QMenuBar::item:selected {
    background-color: #232B39;
    color: #F8FAFC;
}

/* 頂部導航/狀態 Bar */
#TopBar {
    background-color: #1A1F29;
    border: 1px solid #283040;
    border-radius: 10px;
    padding: 8px 14px;
}

/* 標籤頁 QTabWidget */
QTabWidget::pane {
    border: 1px solid #232B39;
    background-color: #161A22;
    border-radius: 8px;
    top: -1px;
}

QTabBar::tab {
    background: #1A1F29;
    color: #94A3B8;
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    border: 1px solid #242D3D;
    border-bottom: none;
    font-weight: 500;
}

QTabBar::tab:selected {
    background: #161A22;
    color: #38BDF8;
    border-top: 2px solid #38BDF8;
}

QTabBar::tab:hover:!selected {
    background: #232B39;
    color: #CBD5E1;
}

/* 群組框 (分頁內區塊) */
QGroupBox {
    background-color: #161A22;
    border: 1px solid #232B39;
    border-radius: 8px;
    margin-top: 14px;
    padding: 12px 10px 8px 10px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    color: #94A3B8;
}

/* 頁首 (標題 + 說明) */
#PageTitle { font-size: 20px; font-weight: 600; color: #E2E8F0; }
#PageDesc  { font-size: 12px; color: #94A3B8; }

/* 卡片式分層表面 */
#Card {
    background-color: #161A22;
    border: 1px solid #232B39;
    border-radius: 8px;
}
#CardTitle { font-size: 14px; font-weight: 600; color: #E2E8F0; }
#CardDesc  { font-size: 12px; color: #94A3B8; }

/* 分段控制項 (Segmented Control) */
#Seg {
    background-color: #1A1F29;
    border: 1px solid #242D3D;
    border-radius: 8px;
}
QPushButton#SegItem {
    border: none;
    border-radius: 6px;
    padding: 5px 16px;
    background: transparent;
    color: #94A3B8;
    font-weight: 500;
}
QPushButton#SegItem:hover { background-color: #232B39; color: #CBD5E1; }
QPushButton#SegItem:checked {
    background-color: #0284C7;
    color: #FFFFFF;
    font-weight: 600;
}

/* 按鈕設計 */
QPushButton {
    background-color: #242D3D;
    color: #F1F5F9;
    border: 1px solid #334155;
    padding: 6px 14px;
    border-radius: 6px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #475569;
}

QPushButton:pressed {
    background-color: #1E293B;
}

QPushButton:disabled {
    background-color: #1B212D;
    color: #64748B;
    border-color: #2C3646;
}

/* 主要動作按鈕 */
QPushButton#PrimaryBtn {
    background-color: #0284C7;
    border: 1px solid #38BDF8;
    color: #FFFFFF;
}
QPushButton#PrimaryBtn:hover {
    background-color: #0369A1;
}

/* 成功按鈕 (如啟動) */
QPushButton#SuccessBtn {
    background-color: #10B981;
    border: 1px solid #34D399;
    color: #FFFFFF;
    font-weight: 600;
}
QPushButton#SuccessBtn:hover {
    background-color: #059669;
}

/* 危險/停止按鈕 */
QPushButton#DangerBtn {
    background-color: #EF4444;
    border: 1px solid #F87171;
    color: #FFFFFF;
}
QPushButton#DangerBtn:hover {
    background-color: #DC2626;
}

/* 警示/編輯中按鈕 */
QPushButton#WarnBtn {
    background-color: #D97706;
    border: 1px solid #FBBF24;
    color: #FFFFFF;
    font-weight: 600;
}
QPushButton#WarnBtn:hover {
    background-color: #B45309;
}

/* 次要/幽靈按鈕 */
QPushButton#GhostBtn {
    background-color: transparent;
    border: 1px solid #334155;
    color: #CBD5E1;
}
QPushButton#GhostBtn:hover {
    background-color: #232B39;
}

/* 輸入框與下拉框 */
QLineEdit, QComboBox, QSpinBox {
    background-color: #1E2430;
    color: #F8FAFC;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: #0284C7;
    selection-color: #FFFFFF;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #38BDF8;
    background-color: #242C3C;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #94A3B8;
    margin-right: 8px;
}
QSpinBox::up-button, QSpinBox::down-button {
    background-color: #242D3D;
    border: none;
    width: 16px;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #334155;
}

/* 清單 */
QListWidget {
    background-color: #161A22;
    border: 1px solid #232B39;
    border-radius: 8px;
    outline: none;
}
QListWidget::item {
    padding: 5px 8px;
    border-radius: 4px;
}
QListWidget::item:selected {
    background-color: #263347;
    color: #F8FAFC;
}
QListWidget::item:hover:!selected {
    background-color: #1F2735;
}

/* 表格現代化樣式 */
QTableWidget {
    background-color: #161A22;
    border: 1px solid #232B39;
    border-radius: 8px;
    gridline-color: #1F2735;
    selection-background-color: #263347;
    selection-color: #F8FAFC;
}

QHeaderView::section {
    background-color: #1B212D;
    color: #94A3B8;
    padding: 8px 12px;
    border: none;
    border-bottom: 2px solid #242D3D;
    font-weight: 600;
}

QTableWidget::item {
    padding: 6px 10px;
    border-bottom: 1px solid #1C2330;
}

QTableWidget::item:selected {
    background-color: #223046;
}

/* 日誌輸出 */
QTextEdit#LogView {
    background-color: #0F1319;
    color: #86EFAC;
    border: 1px solid #232B39;
    border-radius: 8px;
    font-family: Consolas, 'Courier New', monospace;
    selection-background-color: #0284C7;
    selection-color: #FFFFFF;
}

/* 滾動條樣式 (垂直 + 水平) */
QScrollBar:vertical {
    background: #161A22;
    width: 10px;
    margin: 0;
    border: none;
}
QScrollBar:horizontal {
    background: #161A22;
    height: 10px;
    margin: 0;
    border: none;
}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: #334155;
    border-radius: 5px;
    min-height: 28px;
    min-width: 28px;
}
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {
    background: #475569;
}
QScrollBar::add-line, QScrollBar::sub-line {
    width: 0;
    height: 0;
    background: none;
    border: none;
}
QScrollBar::add-page, QScrollBar::sub-page {
    background: none;
}

/* 捲軸交會角 / 表格左上角按鈕 / 表頭空白區 */
QAbstractScrollArea::corner {
    background: #161A22;
    border: none;
}
QTableCornerButton::section {
    background-color: #1B212D;
    border: none;
    border-bottom: 2px solid #242D3D;
}
QHeaderView {
    background-color: #1B212D;
    border: none;
}
QHeaderView::section:vertical {
    border-right: 2px solid #242D3D;
}

/* 核取方塊:自繪深色外觀,避免原生淺色方塊 */
QCheckBox {
    spacing: 8px;
    background: transparent;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid #475569;
    background: #1E2430;
}
QCheckBox::indicator:hover {
    border-color: #38BDF8;
}
QCheckBox::indicator:checked {
    background: #0284C7;
    border-color: #38BDF8;
    image: url(%CHECK_ICON%);
}
QCheckBox::indicator:disabled {
    border-color: #334155;
    background: #1B212D;
}

/* 表格內建勾選框 (QTableWidgetItem 的 ItemIsUserCheckable)
   QCheckBox::indicator 只涵蓋 QCheckBox 元件本身；item view 的勾選指示器由
   delegate 以 ::indicator 子控制項繪製，必須另外指定，否則會以原生外觀畫在
   深色底上，小又不明顯。 */
QTableWidget::indicator, QTableView::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid #475569;
    background: #1E2430;
}
QTableWidget::indicator:hover, QTableView::indicator:hover {
    border-color: #38BDF8;
}
QTableWidget::indicator:checked, QTableView::indicator:checked {
    background: #0284C7;
    border-color: #38BDF8;
    image: url(%CHECK_ICON%);
}

/* 圓形選項按鈕 */
QRadioButton {
    spacing: 8px;
    background: transparent;
}
QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border-radius: 9px;
    border: 1px solid #475569;
    background: #1E2430;
}
QRadioButton::indicator:hover {
    border-color: #38BDF8;
}
/* 選中時以「縮小內容 + 加大邊框」維持指示器外徑 18px (16+2 與 8+10)，
   與未選中一致。若只改 border 寬度會讓外徑變 26px，而 Qt 不會在勾選狀態
   改變時重算 sizeHint，導致文字被裁切 (PID→PI) 與相鄰選項位移。 */
QRadioButton::indicator:checked {
    width: 8px;
    height: 8px;
    border: 5px solid #0284C7;
    background: #F8FAFC;
}

/* 表格內嵌容器(核取方塊外框)不可帶底色 */
QWidget#CellWrap {
    background: transparent;
}

/* 分割器 */
QSplitter::handle {
    background-color: #232B39;
}
QSplitter::handle:horizontal {
    width: 2px;
}
QSplitter::handle:vertical {
    height: 2px;
}

/* 彈出選單 / 提示 / 下拉清單 */
QMenu {
    background-color: #1A1F29;
    border: 1px solid #2C3646;
    border-radius: 6px;
    padding: 4px;
}
QMenu::item {
    padding: 6px 18px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #263347;
    color: #F8FAFC;
}
QToolTip {
    background-color: #1E2430;
    color: #E2E8F0;
    border: 1px solid #334155;
    padding: 4px;
}
QComboBox QAbstractItemView {
    background-color: #1A1F29;
    border: 1px solid #2C3646;
    selection-background-color: #263347;
    outline: none;
}
QMessageBox, QDialogButtonBox {
    background-color: #12151B;
}
"""


_CHECK_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">'
    '<path d="M3.5 8.5l3 3 6-7" fill="none" stroke="#FFFFFF" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def _check_icon_path():
    """把勾選圖示寫成暫存 SVG，供 QSS image: url() 引用 (QSS 不支援 data URI)。"""
    path = os.path.join(tempfile.gettempdir(), "netredirector_check.svg")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_CHECK_SVG)
    except OSError:
        return ""
    return path.replace("\\", "/")


def build_stylesheet():
    """回傳注入勾選圖示路徑後的全域 QSS。"""
    return MODERN_QSS.replace("%CHECK_ICON%", _check_icon_path())


def apply_dark_palette(app):
    """套用 Fusion 樣式與深色 QPalette (QSS 無法覆蓋的原生元件靠此轉深)。"""
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(COLOR_BG))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(COLOR_TEXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(COLOR_PANEL))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor("#1B212D"))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor("#1E2430"))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(COLOR_TEXT))
    pal.setColor(QPalette.ColorRole.Text, QColor(COLOR_TEXT))
    pal.setColor(QPalette.ColorRole.Button, QColor("#242D3D"))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor("#F1F5F9"))
    pal.setColor(QPalette.ColorRole.BrightText, QColor(COLOR_DANGER))
    pal.setColor(QPalette.ColorRole.Link, QColor(COLOR_ACCENT))
    pal.setColor(QPalette.ColorRole.Highlight, QColor("#0284C7"))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor("#64748B"))
    pal.setColor(QPalette.ColorRole.Mid, QColor("#232B39"))
    pal.setColor(QPalette.ColorRole.Dark, QColor("#0F1319"))
    app.setPalette(pal)


# --------------------------------------------------------------- 徽章輔助
# QTableWidget::item 的內距 (見 MODERN_QSS)。塞進儲存格的 widget 也會被這層
# 內距內縮，因此計算欄寬 / 列高時要補回，否則徽章右側與底部會被裁掉。
TABLE_ITEM_PADDING_H = 10
TABLE_ITEM_PADDING_V = 6

BADGE_QSS = ("background-color: #222938; padding: 4px 10px; border-radius: 12px;"
             " border: 1px solid #334155; color: %s;")


def style_badge(label, color):
    """把 QLabel 套成狀態膠囊 (Pill / Badge)。"""
    label.setStyleSheet(BADGE_QSS % color)


def set_button_kind(button, kind):
    """切換按鈕的 objectName (PrimaryBtn/SuccessBtn/DangerBtn/WarnBtn/GhostBtn)
    並重新 polish，讓 QSS 立即生效。"""
    if button.objectName() == kind:
        return
    button.setObjectName(kind)
    style = button.style()
    style.unpolish(button)
    style.polish(button)
