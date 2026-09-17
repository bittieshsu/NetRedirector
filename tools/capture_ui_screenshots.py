# -*- coding: utf-8 -*-
"""離屏渲染 NetRedirector 各分頁/對話框，產出 docs/images 的說明用截圖。

以 QT_QPA_PLATFORM=offscreen 在獨立行程中重建 MainWindow，並用樁模組取代
DLL 橋接、網路監控執行緒與所有會動到系統的呼叫（工作排程器、介面計量、
連接埠監聽、更新檢查），所以正在執行的實例完全不受影響。

用法:
    python tools/capture_ui_screenshots.py
"""

import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

# 注意：不可使用 QT_QPA_PLATFORM=offscreen。該外掛在 Windows 上的字型
# 資料庫是空的（QFontDatabase.families() 回傳 0 個），中文會全部變成方框。
# 改用原生平台 + WA_DontShowOnScreen：排版與算圖都正常，但視窗不會真的
# 顯示到螢幕上，因此仍不會干擾正在執行的實例。

from PySide6.QtCore import QObject, Signal, Qt            # noqa: E402
from PySide6.QtGui import QColor, QPainter, QPixmap       # noqa: E402
from PySide6.QtWidgets import QApplication                # noqa: E402

import ui_theme                                           # noqa: E402
import IntegratedApp                                      # noqa: E402
from tabs_rules import RuleDialog                         # noqa: E402
from tabs_proxies import ProxyDialog                      # noqa: E402

OUT = os.path.join(ROOT, "docs", "images")
WIN_W, WIN_H = 1600, 900


# --------------------------------------------------------------------- 樁模組
class _StubBridge:
    """取代 NetRedirectorWrapper：不載入 DLL、不呼叫 WinDivert。"""

    def __init__(self, *args, **kwargs):
        self.lib = types.SimpleNamespace()   # 無 DeleteProxyConfig → 走 fallback
        self._next_id = 9000

    def _new_id(self):
        self._next_id += 1
        return self._next_id

    def set_log_callback(self, *a, **k):
        pass

    def set_connection_callback(self, *a, **k):
        pass

    def add_proxy(self, *a, **k):
        return self._new_id()

    def add_rule_ex(self, *a, **k):
        return self._new_id()

    def edit_rule_ex(self, *a, **k):
        return True

    def delete_rule(self, *a, **k):
        return True

    def start(self):
        return True

    def stop(self):
        pass


class _StubMonitor(QObject):
    """取代 NetworkMonitorWorker：不做任何 ping 或介面掃描。"""

    data_updated = Signal(dict)

    def __init__(self, *args, **kwargs):
        super().__init__()

    def start(self):
        pass

    def set_ping_target(self, *a, **k):
        pass

    def set_ping_enabled(self, *a, **k):
        pass


def install_stubs():
    IntegratedApp.NetRedirectorWrapper = _StubBridge
    IntegratedApp.NetworkMonitorWorker = _StubMonitor
    # 啟動時排程的設定載入改為 no-op，資料由本腳本明確注入。
    IntegratedApp.MainWindow.load_config = lambda self: None
    # 不碰工作排程器。
    IntegratedApp.startup.is_supported = lambda: False
    IntegratedApp.startup.is_enabled = lambda: False
    IntegratedApp.startup.enable = lambda: True
    IntegratedApp.startup.disable = lambda: True
    # 不碰 Windows 介面計量。
    IntegratedApp.interface_metrics.ensure_metrics = (
        lambda *a, **k: {"ok": True, "no_vpn": True})
    # 不真的監聽連接埠。
    IntegratedApp.proxy_core.server_controller.start_port = lambda *a, **k: True
    IntegratedApp.proxy_core.server_controller.stop_port = lambda *a, **k: None


# ----------------------------------------------------------------- 示範資料
ONLINE_INTERFACES = {
    "VMware Network Adapter VMnet1": ("192.168.159.1", 6),
    "VMware Network Adapter VMnet8": ("192.168.17.1", 9999),
    "乙太網路": ("192.168.1.200", 7),
    "VPN - VPN Client": ("10.211.254.3", 35),
    "VPN2 - VPN Client": ("10.211.254.4", 48),
}

HUB_PORTS = {
    30677: ["VPN - VPN Client"],
    30678: ["乙太網路", "VPN2 - VPN Client", "VPN3 - VPN Client"],
    30679: ["VMware Network Adapter VMnet1"],
}
SELECTED_PORT = 30678

PROXIES = [
    {"id": 2001, "name": "MyPhone", "type": "SOCKS5", "ip": "192.168.1.178",
     "port": 1080, "user": "", "pass": "",
     "latency": "42ms (IP: 49.215.47.154)", "status_color": "green"},
    {"id": 2002, "name": "Office HTTP", "type": "HTTP", "ip": "10.20.30.40",
     "port": 8080, "user": "proxyuser", "pass": "secret",
     "latency": "318ms (IP: 203.0.113.7)", "status_color": "orange"},
    {"id": 2003, "name": "Backup VPS", "type": "SOCKS5", "ip": "203.0.113.88",
     "port": 1080, "user": "", "pass": "",
     "latency": "失敗: 超時", "status_color": "red"},
]

HUB_PROXY_MAP = {30677: 1901, 30678: 1902, 30679: 1903}

RULES = [
    {"id": 101, "enabled": True, "type": "Name", "target": "chrome.exe",
     "hosts": "*", "ports": "*", "proto": "BOTH",
     "action": "PROXY (轉發)", "action_key": 0,
     "proxy": "[Custom] MyPhone", "proxy_name": "custom:MyPhone", "proxy_id": 2001},
    {"id": 102, "enabled": True, "type": "Name", "target": "game.exe",
     "hosts": "*", "ports": "*", "proto": "BOTH",
     "action": "DIRECT (直連)", "action_key": 1,
     "proxy": "未指定 (Fallback to Direct)", "proxy_name": "", "proxy_id": 0},
    {"id": 103, "enabled": True, "type": "Name", "target": "*.doubleclick.net",
     "hosts": "*", "ports": "443", "proto": "TCP",
     "action": "BLOCK (阻擋)", "action_key": 2,
     "proxy": "未指定 (Fallback to Direct)", "proxy_name": "", "proxy_id": 0},
    {"id": 104, "enabled": True, "type": "Name", "target": "steam.exe",
     "hosts": "*.steampowered.com;*.steamcontent.com", "ports": "443;27015-27050",
     "proto": "BOTH", "action": "PROXY (轉發)", "action_key": 0,
     "proxy": "[Hub] Local Port 30678", "proxy_name": "hub:30678", "proxy_id": 1902},
    {"id": 105, "enabled": False, "type": "PID", "target": "1234",
     "hosts": "*", "ports": "*", "proto": "UDP",
     "action": "DIRECT (直連)", "action_key": 1,
     "proxy": "未指定 (Fallback to Direct)", "proxy_name": "", "proxy_id": 0},
]

TRAFFIC_ROWS = [
    ("chrome.exe", 13504, "52.79.171.208", 443, "Proxy (TCP)"),
    ("chrome.exe", 13504, "43.203.33.162", 443, "Proxy (TCP)"),
    ("chrome.exe", 13504, "3.37.232.105", 443, "Proxy (TCP)"),
    ("steam.exe", 20884, "23.62.99.180", 443, "Proxy (TCP)"),
    ("steam.exe", 20884, "23.62.99.181", 27015, "Proxy (UDP)"),
    ("Discord.exe", 29588, "162.159.128.233", 443, "Direct (TCP)"),
    ("LINE.exe", 15064, "203.104.153.5", 443, "Direct (TCP)"),
    ("game.exe", 31220, "45.121.34.7", 27015, "Direct (UDP)"),
    ("chrome.exe", 13504, "142.250.192.134", 443, "Blocked (TCP)"),
    ("chrome.exe", 13504, "34.98.64.218", 443, "Blocked (TCP)"),
]

VPN_NICS = [
    ("VPN", "219.100.37.22:443"),
    ("VPN2", "103.147.22.8:443"),
    ("VPN3", ""),
    ("VPN4", "153.121.44.19:995"),
]

SYSTEM_LOG = [
    "系統就緒。",
    "載入節點池完成。",
    "介面計量校正: 虛擬網卡 VPN 計量=10；實體網卡 乙太網路 計量=1",
    "開始測試所有自訂代理 (目標: api.ipify.org)...",
    "[DLL] 測試成功: MyPhone -> 49.215.47.154",
    "[DLL] 測試成功: Office HTTP -> 203.0.113.7",
    "[DLL] 測試失敗: Backup VPS (timeout)",
    "[DLL] 所有代理測試完成。",
    "[DLL] UDP ASSOCIATE established with SOCKS5 proxy ID 1 (192.168.1.178:1080)",
]


# --------------------------------------------------------------------- 工具
def apply_sample_data(win):
    win.current_interfaces = {
        name: {"ipv4": ip, "latency": lat, "connected": True, "ipv6": None}
        for name, (ip, lat) in ONLINE_INTERFACES.items()
    }

    # Hub
    for port in HUB_PORTS:
        win.list_hub_ports.addItem(str(port))
    win.port_config = dict(HUB_PORTS)
    win.hub_proxy_map = dict(HUB_PROXY_MAP)
    for port in HUB_PORTS:
        win.update_hub_list_item(port, True)
    win.list_hub_ports.setCurrentRow(list(HUB_PORTS).index(SELECTED_PORT))
    win.selected_hub_port = SELECTED_PORT
    win.update_hub_status()

    # Proxies / Rules
    win.custom_proxies = [dict(p) for p in PROXIES]
    win.rules = [dict(r) for r in RULES]

    # 讓頂部「活動轉發」徽章有數字
    for name in ("乙太網路", "VPN - VPN Client"):
        win.current_interfaces  # noqa: B018 — 保持可讀性
    try:
        rm = IntegratedApp.proxy_core.route_manager
        rm.interfaces.setdefault("乙太網路", {})["active_conns"] = 14
        rm.interfaces.setdefault("VPN - VPN Client", {})["active_conns"] = 6
    except Exception as exc:  # noqa: BLE001
        print("warn: 無法設定 active_conns:", exc)

    win.refresh_hub_table()
    win.refresh_custom_proxy_table()
    win.refresh_rules_table()

    # Monitor
    for proc, pid, ip, port, info in TRAFFIC_ROWS:
        win.append_traffic_row(proc, pid, ip, port, info)

    # VPN Gate：節點清單來自實際的 vpn_history.json（setup 階段已載入），
    # 這裡只補上網卡清單。
    win._vpn_render_nics(list(VPN_NICS))

    # 系統日誌
    win.txt_log.clear()
    for line in SYSTEM_LOG:
        win.append_log(line)

    win.is_redirector_running = True
    win.update_service_status()


def grab_tab(win, app, index):
    win.tabs.setCurrentIndex(index)
    app.processEvents()
    app.processEvents()
    return win.grab()


def save(pixmap, name):
    path = os.path.join(OUT, name)
    ok = pixmap.save(path, "PNG")
    print("  %-12s %sx%s  %s" % (name, pixmap.width(), pixmap.height(),
                                 "OK" if ok else "FAIL"))
    return ok


def compose(base, overlay):
    """把對話框疊到主視窗截圖正中央（模擬模態視窗）。"""
    out = QPixmap(base.size())
    out.fill(QColor(0, 0, 0, 0))
    painter = QPainter(out)
    painter.drawPixmap(0, 0, base)
    x = (base.width() - overlay.width()) // 2
    y = (base.height() - overlay.height()) // 2
    painter.fillRect(x + 8, y + 8, overlay.width(), overlay.height(),
                     QColor(0, 0, 0, 120))
    painter.drawPixmap(x, y, overlay)
    painter.end()
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    install_stubs()

    app = QApplication(sys.argv)
    ui_theme.apply_dark_palette(app)
    app.setStyleSheet(ui_theme.build_stylesheet())

    win = IntegratedApp.MainWindow()
    # 避免 1.2 秒後的啟動更新檢查真的連網。
    win.check_updates_on_start = False
    win.resize(WIN_W, WIN_H)
    win.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    win.show()
    app.processEvents()
    app.processEvents()

    apply_sample_data(win)

    # 關掉背景計時器，避免截圖期間畫面變動。
    for attr in ("vpn_timer", "vpn_monitor_timer", "vpn_auto_timer",
                 "_traffic_scroll_timer"):
        timer = getattr(win, attr, None)
        if timer is not None:
            timer.stop()

    app.processEvents()

    print("產出截圖:")
    hub = grab_tab(win, app, 0)
    save(hub, "1.png")

    rules = grab_tab(win, app, 1)
    save(rules, "2-2.png")

    proxies = grab_tab(win, app, 2)
    save(proxies, "3-2.png")

    monitor = grab_tab(win, app, 3)
    save(monitor, "4.png")

    vpngate = grab_tab(win, app, 4)
    save(vpngate, "5.png")

    # 表單對話框：疊在對應分頁上，維持與舊圖相同的整體外觀。
    rule_dlg = RuleDialog(win, proxy_choices=win.proxy_choices())
    rule_dlg.ent_target.setText("chrome.exe")
    rule_dlg.ent_hosts.setText("*")
    rule_dlg.ent_ports.setText("*")
    rule_dlg.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    rule_dlg.show()
    app.processEvents()
    app.processEvents()
    save(compose(rules, rule_dlg.grab()), "2-1.png")
    rule_dlg.hide()

    proxy_dlg = ProxyDialog(win)
    proxy_dlg.ent_name.setText("MyPhone")
    proxy_dlg.ent_ip.setText("192.168.1.178")
    proxy_dlg.ent_port.setText("1080")
    proxy_dlg.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    proxy_dlg.show()
    app.processEvents()
    app.processEvents()
    save(compose(proxies, proxy_dlg.grab()), "3-1.png")
    proxy_dlg.hide()

    # 啟動 / 停止狀態（頂部控制列）
    win.is_redirector_running = True
    win.update_service_status()
    win.tabs.setCurrentIndex(0)
    app.processEvents()
    save(win.grab(), "start.png")

    win.is_redirector_running = False
    win.update_service_status()
    for port in HUB_PORTS:
        for i in range(win.list_hub_ports.count()):
            item = win.list_hub_ports.item(i)
            if item.text().startswith(str(port)):
                item.setText(str(port))
    win.txt_log.clear()
    win.append_log("服務已停止，驅動解除攔截。")
    app.processEvents()
    save(win.grab(), "stop.png")

    print("DONE")


if __name__ == "__main__":
    main()
