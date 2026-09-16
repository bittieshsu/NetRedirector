"""Configuration for VPN Gate auto-assign."""

import os

# SoftEther VPN Client vpncmd.exe path (Simplified Chinese build, v4.44)
VPNCMD_PATH = r"C:\Program Files\SoftEther VPN Client\vpncmd.exe"

# VPN Gate real-time node list (CSV format)
VPNGATE_API_URL = "http://www.vpngate.net/api/iphone/"

# Virtual HUB name used by all VPN Gate public relays
VPNGATE_HUB = "VPNGATE"

# Anonymous auth username used by VPN Gate
VPNGATE_USERNAME = "vpn"

# NICs currently in active use (do NOT touch)
ACTIVE_NICS = [f"VPN{i}" for i in range(2, 12)]  # VPN2..VPN11

# NICs opened for testing
TEST_NICS = ["VPN12", "VPN13", "VPN14"]

# Number of connections to manage in production (VPN2..VPN11)
PRODUCTION_NIC_COUNT = 10

# 介面計量管理：SoftEther 虛擬網卡建立時 IPv4 計量為「自動」，且 SoftEther
# 預設會把 VPN 設成預設閘道，多張網卡連線後會與實體網卡搶 0.0.0.0/0 路由。
# 啟用後在啟動與重新整理網卡時，自動把虛擬網卡計量設為 VPN_INTERFACE_METRIC、
# 承接預設路由的實體網卡設為 PHYSICAL_INTERFACE_METRIC，確保實體網卡是主網路。
MANAGE_INTERFACE_METRIC = True
VPN_INTERFACE_METRIC = 10
PHYSICAL_INTERFACE_METRIC = 1

# Connection / verification timeouts (seconds)
CONNECT_TIMEOUT = 10
STATUS_POLL_INTERVAL = 2

# 自動連線/手動派發的平行連線 worker 數 (同時連幾張網卡)
PARALLEL_ASSIGN_WORKERS = 8

# 自動連線:勾選後每隔此秒數掃描一次離線網卡並自動派發候選節點
AUTO_CONNECT_INTERVAL = 30

# SoftEther 連線設定的進階選項 (套用於每個 VPN Gate 帳號)
# MAXTCP: VPN 通訊使用的 TCP 連線數 (1..32)
ACCOUNT_MAX_TCP = 3
# 斷線/連線失敗後的自動重連次數;0 = 不自動重連,由本程式改派其他節點
ACCOUNT_RETRY_NUM = 0

# 批次查 IP：SoftEther 在 session 顯示連線完成後才派發 TAP IP，有短暫延遲，
# 對還沒拿到 IP 的網卡重新輪詢整個介面清單。
IP_POLL_INTERVAL = 0.5
IP_WAIT_TIMEOUT = 5.0

# tunnel 可達性驗證重試 (IP 剛出現時路由可能尚未收斂，避免誤判為未連線成功)
TUNNEL_CHECK_ATTEMPTS = 2
TUNNEL_CHECK_RETRY_DELAY = 1.0

# vpncmd output encoding (Simplified Chinese build v4.44 actually emits UTF-8)
VPNCMD_ENCODING = "utf-8"

# Minimum acceptable Speed (bps) reported by VPN Gate
MIN_SPEED_BPS = 10_000_000  # 10 Mbps

# Persistent node pool (vpn_history.py)
VPN_HISTORY_FILE = "vpn_history.json"
HISTORY_PRUNE_MAX_NODES = 800
HISTORY_PRUNE_MAX_AGE_DAYS = 30

# Stability score weights: (connect_rate, tunnel_rate, duration, kick, fail)
STABILITY_WEIGHTS = (0.35, 0.25, 0.30, 0.10, 0.20)
STABILITY_DURATION_FULL_SEC = 3600  # 平均 session 達此秒數 = 該維度滿分
STABILITY_KICK_FULL = 10            # 被踢達此次數 = 懲罰滿分
STABILITY_FAIL_CAP = 5              # 連續失敗懲罰上限

# Session monitor: detects offline AND zombie (SoftEther 顯示連線但 tunnel 已死)
SESSION_POLL_INTERVAL = 10   # 每輪檢查間隔 (秒)
MONITOR_TUNNEL_TIMEOUT = 3   # 監視器 tunnel 探測的短 timeout (秒)
TUNNEL_DEAD_THRESHOLD = 3    # 連續 N 次 tunnel 不可達才判定假死
