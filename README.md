# NetRedirector

NetRedirector 是一個功能強大的網路流量轉發和代理工具，結合了本地端口路由和系統級流量攔截功能。它提供了圖形化界面，讓用戶可以輕鬆管理多個網路介面和代理規則。

## 功能特色

### 1. 端口路由管理 (Hub)
- 支援多個本地監聽端口
- 可將不同端口綁定到不同的網路介面
- 自動選擇最佳延遲的網路介面進行連線
- 每個端口可綁定多個網路介面
- 支援介面篩選功能，快速搜尋指定介面
- 支援全選顯示項目功能

### 2. 進程攔截規則 (Rules)
- 支援按進程名稱或 PID 設定規則
- 可指定目標主機和端口
- 支援 TCP/UDP 協議篩選
- 三種規則動作：代理、直連、阻擋
- 支援規則編輯功能，可修改現有規則
- 可將規則與特定代理綁定

### 3. 自訂代理管理
- 支援 SOCKS5 和 HTTP 代理
- 可設定帳號密碼驗證
- 可將規則與特定代理綁定
- 支援代理連線測試功能，驗證代理可用性

### 4. 流量監控
- 實時顯示網路流量
- 顯示進程名稱和 PID
- 目標 IP 和端口資訊
- 支援右鍵點擊流量記錄快速新增規則

### 5. 故障轉移與負載平衡
- 支援多網卡故障轉移機制
- 當主要介面失效時自動切換到備用介面
- 智能負載平衡，避免單一介面過載

### 6. IPv6 支援
- WinDivert 攔截層完整支援 IPv4 / IPv6 雙棧
- IPv6 目標流量可經由 SOCKS5 代理轉發（SOCKS5 ATYP_IPV6 / HTTP CONNECT `[IPv6]:port`）
- IPv6 規則比對支援完整位址或 `*` 萬用
- IPv6 multicast / link-local / loopback 流量自動直連

### 7. 區域網路自動直連
- 目的地為私有網段（IPv4 `10/8`、`172.16/12`、`192.168/16`，IPv6 ULA `fc00::/7`）時自動直連
- 目的地與本機任一張作用中網卡位址同網段（on-link）時自動直連（含 ISP 派發的全球 IPv6，例如 `2001:b011:xxxx::/64`）
- 確保區網內檔案傳輸不會經由外部代理（如手機 SOCKS5 5G 上網）繞路，傳檔速度不受代理影響

## 系統需求

- Windows 10/11
- 管理員權限 (用於安裝 WinDivert 驅動)
- Python 3.7+
- 高效網路診斷功能 (使用內建 network_utils 模組替代傳統 cmd 命令)

## 安裝步驟

1. 確保系統安裝了 Python 3.7+
2. 下載專案檔案
3. 安裝相依套件：`pip install -r requirements.txt`
4. 以管理員身份執行 `IntegratedApp.py`

## 使用說明

### 端口路由管理
1. 在 "1. 端口路由管理" 分頁中新增本地監聽端口
2. 選擇端口後，在右側表格中勾選要綁定的網路介面
3. 可使用篩選框快速搜尋指定介面名稱
4. 點擊 "全選顯示項目" 可快速選取所有顯示的介面
5. 點擊 "啟動/重啟選中端口" 開始服務
6. 其他應用程式可以透過設定的本地端口進行代理連線

### 進程攔截規則
1. 在 "2. 進程攔截規則" 分頁中設定規則
2. 選擇規則類型 (進程名稱或 PID)
3. 輸入目標 (如 chrome.exe 或 PID 1234)
4. 設定進階條件 (目標主機、端口、協議)
5. 選擇規則動作和指定代理
6. 點擊 "新增規則" 儲存
7. 可雙擊規則項目進行編輯修改

### 自訂代理管理
1. 在 "3. 自訂代理管理" 分頁中新增外部代理
2. 輸入代理名稱、類型、IP、端口等資訊
3. 如需要，設定帳號密碼驗證
4. 點擊 "新增代理" 儲存代理設定
5. 可點擊 "測試所有代理連線 (Ping)" 測試代理可用性

### 高效網路診斷工具
NetRedirector 提供了比傳統 Windows `ping` 和 `ipconfig` 命令更高效的網路診斷功能：

- **高效網路介面檢測**：使用 `network_utils.get_system_interfaces()` 代替 `ipconfig`
- **精確延遲測試**：使用 `network_utils.ping_address()` 代替傳統 `ping` 命令
- **實時監控**：內建網路介面延遲監控，無需額外命令列工具

這些內建工具提供更快的響應速度和更豐富的資訊，無需調用外部命令列程序。

### 流量監控
1. 在 "4. 流量監控" 分頁中檢視即時流量
2. 可以右鍵點擊流量記錄快速新增規則

## 檔案結構

```
NetRedirector/
├── IntegratedApp.py         # 整合版主應用程式 (GUI)
├── GameProxyHub.py          # 原始端口路由管理界面
├── proxy_core.py            # 本地 SOCKS5 代理核心 (Hub 模式)
├── network_utils.py         # 網路介面掃描工具
├── NetRedirector.py         # NetRedirector DLL 包裝器
├── NR_simple.py             # 簡易測試版本
├── config.json              # 本地設定檔 (由程式自動產生/讀取)
├── requirements.txt         # Python 相依套件
├── NetRedirector.dll        # 核心 C 語言 DLL
├── WinDivert.dll           # WinDivert 動態連結庫
├── WinDivert64.sys          # WinDivert 驅動程式
├── vcruntime140.dll        # VC++ 執行時期庫
└── NetRedirector/           # C 語言原始碼
    ├── NetRedirector.c      # DLL 導出函數
    ├── NR_Core.c            # 封包處理 (WinDivert) 與 UDP Relay
    ├── NR_Protocol.c        # SOCKS5 / HTTP 協議實作
    ├── NR_RuleEngine.c      # 規則引擎
    ├── NR_State.c           # 連線狀態追蹤
    ├── NR_Utils.c           # 工具函式
    ├── windivert.h          # WinDivert SDK 標頭
    ├── WinDivert.lib        # WinDivert 匯入函式庫
    └── build_dll.bat        # 重新編譯 DLL 腳本 (需 MSVC x64)
```

## 重新編譯 DLL

C 核心以 Visual Studio 編譯，需要 MSVC x64 工具鏈：

```
build_dll.bat
```

輸出為 `NetRedirector/NetRedirector.dll`，取代根目錄的同名檔案後生效。

## 技術架構

- 前端：PySide6 GUI 框架
- 後端：Python 套件
- 核心：C 語言 DLL (基於 WinDivert)
- 網路協定：SOCKS5 (支援 IPv4 / IPv6 目標) / HTTP CONNECT
- 攔截技術：WinDivert 核心層封包攔截 (IPv4 + IPv6 雙棧)

## 注意事項

1. 必須以管理員權限執行應用程式
2. 首次執行時可能需要允許 WinDivert 驅動程式安裝
3. 防火牆可能會阻止應用程式的網路存取
4. 某些防毒軟體可能將此應用程式標記為威脅
5. 故障轉移功能可在主要連線失效時自動切換至備用連線

## 授權

此專案使用 MIT 授權 - 詳見 [LICENSE](LICENSE) 檔案。

## 貢獻

歡迎提交 Issue 和 Pull Request 來改善此專案。