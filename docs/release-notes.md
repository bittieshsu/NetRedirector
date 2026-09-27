# NetRedirector v1.8.2

## 效能修正：解除約 200 Mbps 的吞吐天花板，並大幅降低新連線的延遲

這一版是針對核心轉發引擎（NetRedirector.dll）的效能修正。起因是本機實測發現：
經過 NetRedirector 的單一連線只能跑約 190 Mbps，而同一條網路路徑直通時可以跑 260–300 Mbps。
完整診斷過程與實測數據記錄在 `docs/perf-diagnosis-2026-09-27.md`。

### 1. 解除吞吐天花板：不再把接收緩衝釘死在 64 KB

通道 socket 原本呼叫 `setsockopt(SO_RCVBUF, 64KB)`。在 Windows 上，**只要呼叫了 `setsockopt(SO_RCVBUF)`，
該 socket 的接收視窗自動調整就會失效**，視窗從此被綁在 64 KB 附近。以實測的通道 RTT（約 2.5 ms）計算，
64 KB ÷ 2.5 ms ≈ 210 Mbps —— 這正是觀察到的天花板。

三臂交錯受控實驗（同一目的地、同一檔案，只差這行 setsockopt）：

| socket 設定 | 平均 | 最差 |
|---|---|---|
| `setsockopt(SO_RCVBUF, 64KB)` | 230.9 Mbps | 171.6 Mbps |
| 不呼叫 setsockopt（自動調整） | 281.0 Mbps | 263.7 Mbps |
| `setsockopt(SO_RCVBUF, 256KB)` | 279.2 Mbps | 261.5 Mbps |

修正方式：**移除該行，讓 Windows 的自動調整生效**（不是把數值加大而已 —— 重點在於「有沒有呼叫它」，
Windows 的預設值本來就是 65536，但不呼叫時自動調整仍然有效）。

### 2. 中繼自己的通道流量不再進入使用者模式

WinDivert 濾鏡原本是 `tcp and outbound`，會把中繼自己連往代理伺服器的通道封包也一起攔下。
這些封包最終一定判定為 DIRECT、不修改任何欄位，卻仍走完「recv → parse → 雜湊 → 配置記憶體 →
排隊 → 喚醒 worker → 再 parse → 重算 checksum → 送回」的整趟使用者模式流程 —— 也就是
**100% 的代理流量都為一個永遠是「不要動它」的決定付了一次完整來回**。

修正方式：新增 `build_windivert_filter()`，對每個已啟用的代理端點加上排除條件。
排除條件同時比對**位址與埠**（address AND port）—— 只排除位址的話，連到同一台主機其他埠的連線
也會被漏成 DIRECT，那就是真實 IP 外洩。主機名形式的代理位址會被安全跳過（濾鏡語言沒有 DNS），
只記 warning、不影響啟動。

### 3. 沒改寫的封包不再重算 checksum

原本所有被攔下的封包都無條件重算 checksum。實際上「判定為 DIRECT」與「來自代理端點的入站封包」
這兩類完全沒有改寫任何欄位，其 checksum 本來就是有效的。修正後只在真的改寫過時才重算。

### 4. 封包佇列：不再每包 malloc，worker 一次喚醒排空整批

原本每一個封包都要 `malloc` 一份拷貝、並用一個 counting semaphore 交棒给 worker。
在 1 個接收執行緒 + 3 個 worker 的情況下，等於全部執行緒都在爭用處理程序堆積（heap 最不擅長的
正是這種固定大小、極短生命週期的物件）。

修正方式：環狀佇列的每個槽位預先配置緩衝區（2048 B，必要時才成長）並重複使用；
semaphore 換成 auto-reset event，worker 改成一次喚醒就排空整個 backlog。

### 5. UDP relay 每輪排空整批 datagram

原本每個 socket 每輪 `select()` 只收一個 datagram，所以一陣突發流量要付出一次 `select()`
系統呼叫 per datagram。修正後以 `FIONREAD` 探測是否還有待收資料，在單輪內排空（上限 64 個）。

### 6. 防火牆規則不再無限累加

`netsh advfirewall firewall add rule` **不會**取代同名規則，而是再新增一條。
因此任何沒有配對到成功 Stop 的 Start（程式崩潰、被強制結束、Stop 失敗）都會留下規則，
每次啟動再加一條 —— 本機實測已累積 **118 條**（59 TCP + 59 UDP）。

修正方式：新增規則前先刪除同名規則（靜默，因為規則不存在時 netsh 本來就回非零），
而 `delete rule name=...` 會刪掉**所有**同名規則，所以順帶清掉既有的積累。

### 7. 新連線的行程查詢改走 socket 事件快取

每條新連線都要查詢「這個連線屬於哪個行程」，原本的做法是快照整份系統連線表
（`GetExtendedTcpTable`），實測約 **650 µs/次，而且是固定成本**（468 列與 173 列的 IPv6 表都是 ~640 µs，
去掉 owner-PID 欄位也要 621 µs）。這是整個專案單價最高的操作：開 100 條連線的網頁 =
65–130 ms 的純系統呼叫開銷，而且它跑在 flow worker 上、會讓同一條 flow 的封包排隊。

修正方式：新增 `NR_PidMap.c`，開一個 WinDivert SOCKET 層 handle，用 socket 生命週期事件維護
`(協定, 本地埠) → pid` 的快取表。**先查快取，miss 才回退原本的系統表** —— 命中時 650 µs → 約 0.1 µs，
競態時行為與修正前完全相同。安全設計：

- **fail closed**：同一個 `(協定, 埠)` 出現兩個不同 pid 時該槽停止作答（回 miss，走權威表），
  所以快取只可能是捷徑，不可能給出錯誤答案。
- **可選加速器**：handle 開不起來時只記 log，所有查詢走原本的系統表，絕不讓 `Start()` 失敗。
- 停止時會在 log 輸出命中率統計（例如 `PID map: 38/40 process lookups served from socket events (95%)`）。

> 補充：SOCKET 層必須帶 `WINDIVERT_FLAG_SNIFF`。官方文件寫只要 `RECV_ONLY`，**照做會讓全機的
> `bind()` 回 `WSAEACCES (10013)`**（實測 0/12 可建立）。本版已硬性固定為 `SNIFF | RECV_ONLY`。

---

## 測試

- **C 測試套件 222/222 通過**（`test_dns_snoop 29`、`test_filter 21`、`test_lock_stress 1`、
  `test_rules 24`、`test_state 62`、`test_udp_rewrite 22`、`test_utils 63`）。
- 新增 `tests/test_filter.c`（21 項）：以 `WinDivertHelperCompileFilter` / `EvalFilter`
  （純使用者模式、不需驅動與管理員）**同時建構舊與新兩份濾鏡**逐案例比對，
  斷言「行為差異恰好等於預期的 4 個通道案例，其餘 bit-for-bit 不變」。
  含「同一台代理主機的其他埠仍會被攔截」的 IP 外洩防護回歸測試。
- 新增基準／探針程式：`bench_conn_lookup.c`、`bench_packet_helpers.c`、`bench_pid_cache.c`、
  `probe_flow_layer.c`、`probe_pid_map.c`、`probe_socket_layer_safety.c`。
  pid 快取的正確性閘門：與權威系統表比對 **TCP 24/24、UDP 16/16 一致，CONFLICT 0**。

---

## 尚未量測的部分

- **端到端增益未量測**：替換執行中的 DLL 需要關閉 `IntegratedApp.exe`，本版尚未重跑完整的
  交錯 A/B 測速。「吞吐回到 260–280 Mbps」與「新連線延遲改善」在目前仍屬推論而非實測。
- 修復後的實際命中率請看停止時的 log（`PID map: ...`）。

> 提醒：這些修正都在 NetRedirector.dll（核心引擎）與執行檔內。使用內建自動更新即可取得；
> 若更新程式本身卡住，請直接下載本頁 zip 手動覆蓋。
