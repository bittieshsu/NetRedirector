# NetRedirector 效能診斷報告（PC 測速 ~200 Mbps vs Pad 300+ Mbps）

日期：2026-09-27（第 2 版，取代同日第 1 版）
受測：NetRedirector.dll 2026-09-22（IntegratedApp.exe PID 55808）
環境：PC `192.168.1.200`（Intel I211 有線 1 Gbps，**PPPoE 固網 ~92 Mbps**）
　　　→ 路由器 `192.168.1.2` → Wi-Fi → Pad `192.168.1.178:1080`（5G-Proxy-Pro，**5G 行動網路**）

---

## 0. 結論

**NetRedirector 有一個已量化、可重現的缺陷，就是它造成 PC 端 ~200 Mbps 的主因。**

`NR_Core.c:747,754-755` 把通道 socket 的 `SO_RCVBUF` 硬釘在 **64 KB**。
在 Windows 上，**一旦應用程式呼叫 `setsockopt(SO_RCVBUF)`，該 socket 的接收視窗自動調整就會被關掉**，
視窗從此被綁在 64 KB 附近。以實測的通道 RTT（清醒時 2–3 ms）計算，
64 KB ÷ 2.5 ms ≈ 210 Mbps —— 這就是天花板。

受控實驗（見 §2）證實：同一個目的地、同一個檔案、交錯重複量測，

| socket 設定 | 平均 | 最差 | 最好 |
|---|---|---|---|
| `setsockopt(SO_RCVBUF, 64KB)` | **230.9 Mbps** | **171.6** | 281.6 |
| 不呼叫 setsockopt（自動調整） | **281.0 Mbps** | 263.7 | 296.2 |
| `setsockopt(SO_RCVBUF, 256KB)` | **279.2 Mbps** | 261.5 | 294.8 |

→ 64 KB 這一臂平均少 **18%**，最差情況少 **42%**，而 256 KB 就完全恢復。

**⚠️ 更正第 1 版的錯誤結論。** 第 1 版說「主因在 Pad 的 Wi-Fi，NetRedirector 不是主因」——
那是錯的，因為當時用的測速來源（Cloudflare / Vultr）本身就在限速（單線只有 42–82 Mbps），
我把它當成了 PC↔Pad 的能力。改用本地 HiNet 節點後，**PC↔Pad 這段單線可以跑 240–291 Mbps**，
根本不是 200 Mbps 的瓶頸。詳見 §1.2。

---

## 1. 實測數據

### 1.1 路徑延遲

| 目標 | min | avg | max | 遺失 |
|---|---|---|---|---|
| 路由器 `192.168.1.2`（有線段） | 0 ms | **0 ms** | 0 ms | 0% |
| Pad `192.168.1.178`（閒置，20 pkt） | 29 ms | **71 ms** | 123 ms | 0% |
| Pad `192.168.1.178`（閒置，6 pkt） | 2 ms | **23 ms** | 80 ms | 0% |
| Pad `192.168.1.178`（傳輸中，Test-Connection） | 1 ms | — | 6 ms | 0% |

有線段 0 ms。Pad 閒置時平均 23–71 ms、min 只有 2–3 ms —— 這是 **Wi-Fi 省電（PSM）**的典型形狀：
無線電休眠，零星封包要等喚醒。**但這只影響閒置延遲，不是吞吐瓶頸**（見 §1.2）。

### 1.2 吞吐（改用本地 HiNet 測速檔，`--max-time` 截斷量穩態）

`http://http.speed.hinet.net/test_1024m.zip`（注意：該 host 的 https 沒有回應，只有 http 可用）

| 路徑 | 穩態吞吐 |
|---|---|
| PC 直連（自己的 PPPoE） | **92.3 Mbps** |
| PC → Pad SOCKS5，單線 run1 | **239.5 Mbps** |
| PC → Pad SOCKS5，單線 run2 | **277.5 Mbps** |
| PC → Pad SOCKS5，單線 run3 | **290.9 Mbps** |
| PC → Pad SOCKS5，單線 run4 | 268 Mbps（234 MB / 7 s） |
| PC → Pad SOCKS5，單線 run5 | 285 Mbps |
| PC → Pad SOCKS5，單線 run6 | 279 Mbps |

**PC↔Pad 這一段單線就能跑 240–291 Mbps，已接近 Pad 自己測到的 300+。**
所以第 1 版「Wi-Fi 是 200 Mbps 瓶頸」的說法不成立。

> 註：curl `--parallel` 經過 SOCKS5 代理時，多數連線會拿到 0 byte（ttfb 直接等滿 max-time），
> 6 線測試只有 1 條真的在傳。要用多線程得用多個獨立行程，不能靠 curl 的 `--parallel`。

### 1.3 Pad 服務埠探測

`192.168.1.178` 的 1080 / 45407 / 8080 / 80 / 443 / 8888 對 HTTP 一律回 000（無 HTTP 服務），
只有 SOCKS5 1080 可用。Pad 的代理**拒絕 CONNECT 到內網位址**（要求它連 `192.168.1.200:33100` 時
2.6 s 後失敗、http=000），所以無法用「代理回連本機」的方式隔離 Wi-Fi 段。

### 1.4 NetRedirector 現況

- 引擎停止後 `IntegratedApp.exe` 仍在執行、WinDivert 驅動仍在 RUNNING（正常，驅動會留著）。
- 防火牆規則 **118 條**：`NetRedirector Relay TCP 33100` × 59、`... UDP 33200` × 59。
  `NetRedirector_Stop()` 只刪一組，其餘 58 組永久殘留。

---

## 2. 受控實驗：SO_RCVBUF 就是元兇

**方法**：Python 開一個 TCP socket，只差在「有沒有呼叫 `setsockopt(SO_RCVBUF)`」，
經 Pad 的 SOCKS5 抓同一個 HiNet 檔 4 秒，三臂**交錯**跑 6 輪（消除時間漂移）。

```
setsockopt 64KB    n=6  min= 171.6  avg= 230.9  max= 281.6 Mbps
no setsockopt      n=6  min= 263.7  avg= 281.0  max= 296.2 Mbps
setsockopt 256KB   n=6  min= 261.5  avg= 279.2  max= 294.8 Mbps
```

**機制**：Windows 的接收視窗自動調整會在連線期間把視窗（連同緩衝）長到覆蓋 BDP。
以 281 Mbps × 2.5 ms 計算 BDP ≈ **88 KB**，已經大於 64 KB；再遇上 §1.1 那種 80–123 ms 的
延遲尖峰，需要更大。64 KB 不夠 → 傳送端被迫停等 → 吞吐塌陷。

實測 `SO_RCVBUF` 的**預設值本來就是 65536**，但因為沒有呼叫 setsockopt，自動調整仍然有效，
所以「不設定」明顯優於「設定成 64 KB」。**關鍵不是數值大小，是有沒有去呼叫它。**

---

## 3. NetRedirector 的其他缺陷（讀碼確認）

| # | 項目 | 位置 | 說明 |
|---|---|---|---|
| 1 | **`SO_RCVBUF` 釘死 64 KB** | `NR_Core.c:747,754-755` | §2 已量化。**最高優先** |
| 2 | 中繼自己的通道流量被自己的濾鏡攔截 | `NetRedirector.c:633-650` | 濾鏡是 `tcp and outbound`，涵蓋中繼自己那 34 條通往 `192.168.1.178:1080` 的 socket（netstat 實證）。這些封包判為 DIRECT、不改任何欄位，卻仍走完 recv→parse→hash→malloc→佇列→semaphore→再 parse→checksum→send。程式自己在 `NetRedirector.c:619-627` 已為 loopback 做過相同推理 |
| 3 | 沒改寫的封包也重算 checksum | `NR_Core.c:243` | 無條件執行；UDP 分支有正確提前 return，TCP 漏了 |
| 4 | 每封包 malloc + semaphore 交棒 | `NR_Core.c:344-369` | 每封包 2 次 context switch；receiver 與 worker 各 parse 一次；worker 只有 3 條（`NR_Core.c:264`） |
| 5 | 防火牆規則不去重 | `NetRedirector.c:491-511` | add 前未 delete ⇒ 累積 118 條 |
| 6 | UDP/DNS 路徑 | `NR_Core.c:910-1051` | `g_dns_via_proxy=TRUE`；每輪 select 只收一個 datagram，且全程持有 `lock_udp` |

---

## 4. 建議修法（依效益排序）

1. **移除 `NR_Core.c:754-755` 兩行 `setsockopt(SO_RCVBUF)`**（最乾淨），
   或至少改成 ≥256 KB。§2 已證明 256 KB 可完全恢復。
2. 濾鏡排除代理端點：`and (ip.DstAddr != <proxy_ip> or tcp.DstPort != <proxy_port>)`（IPv6 同理）。
3. 只在真的改寫過欄位時才呼叫 `WinDivertHelperCalcChecksums`。
4. 預先配置環狀槽取代每封包 malloc；worker 一次排空多筆；把 parse 結果傳給 worker。
5. 防火牆規則 add 前先 delete 同名（並一次性清掉既有 118 條）。
6. UDP relay 每輪排空 socket。

---

## 5. 端到端 A/B（引擎開著，交錯 5 輪，每輪 6 s，HiNet 1024 MB）

| 輪 | A：中繼（NetRedirector 攔截） | B：直通（LAN → DIRECT） |
|---|---|---|
| 1 | **191.4** Mbps (ttfb 0.12 s) | 300.4 Mbps (ttfb 0.06 s) |
| 2 | **197.5** (0.17 s) | 284.6 (0.07 s) |
| 3 | **182.7** (0.11 s) | 269.7 (0.07 s) |
| 4 | **194.6** (0.09 s) | 243.5 (0.07 s) |
| 5 | 270.0 (0.22 s) — 暖機異常值 | 267.7 (0.09 s) |

引擎關閉時的新鮮基準線：243.4 / 255.8 / 270.7 / 271.3 Mbps（avg ≈ 260）。

**A 臂 5 輪有 4 輪落在 182.7–197.5，精準貼在「64 KB ÷ 2.5 ms ≈ 210 Mbps」的預測上**，
同輪 A vs B 差距 81–217 Mbps。一個數值吻合可能是巧合，但「§2 的隔離實驗」與
「§5 的端到端 A/B」是兩條互相獨立的路徑，都指向同一個天花板。

---

## 6. 修復狀態（2026-09-27 完成）

§3 的 6 項全部已修，另加 flow queue 去 malloc。**C 測試 222/222 通過**
（新增 `tests/test_filter.c` 21 項）。

| # | 項目 | 修法 |
|---|---|---|
| 1 | `SO_RCVBUF` 釘死 64 KB | 移除 `setsockopt`，讓自動調整生效；原地留註解記錄實測數據與「勿再加回」 |
| 2 | 濾鏡攔到中繼自己的通道 | 新增 `build_windivert_filter()`，對每個代理端點加 De Morgan 排除（**address AND port**） |
| 3 | 沒改寫也重算 checksum | 開頭存 `was_outbound`；尾端只在旗標翻轉時重算。所有改寫分支都把 `Outbound` 翻成 FALSE，所以該旗標就是「有沒有改寫」的精確代理指標 |
| 4 | 每封包 malloc + semaphore | slot 內預配置 buffer（2048 B，不夠才 realloc）；counting semaphore 換成 auto-reset event（worker 改成一次喚醒排空整個 backlog，per-packet token 會讓 semaphore 永久超額而空轉） |
| 5 | 防火牆規則不去重 | enable 時先 `delete rule name=...`（quiet）再 add；`delete` 依 name 會刪掉**所有**同名規則，所以順帶清光既有積累（實測 118→120 條） |
| 6 | UDP relay 每輪只收一個 datagram | 新增 `udp_socket_has_pending()`（`FIONREAD`）與上限 64 的排空迴圈，套用於三個讀取點。**沒改 blocking 模式** |

---

## 7. 驗證

- **濾鏡離線驗證**：`WinDivertHelperCompileFilter` / `EvalFilter` 是純使用者模式函式
  （不需驅動、不需管理員）。同時建構**舊與新**兩份濾鏡，逐案例比對，斷言
  **行為差異恰好等於預期的 4 個通道案例**，其餘 bit-for-bit 不變 —— 通過。
  （此法抓到我自己寫錯的兩個預期：「inbound TCP 到任意埠」在**舊濾鏡就已不攔**，不是回歸。）
- **C 測試套件**：`test_dns_snoop 29/29`、`test_filter 21/21`、`test_lock_stress 1/1`、
  `test_rules 24/24`、`test_state 62/62`、`test_udp_rewrite 22/22`、`test_utils 63/63`。
- **DLL 已重建**（MSVC，僅既有 C4819 字碼頁警告），並以**符號配對**證明新舊不同：
  新字串 5 個 0→1、被刪字串 1 個 1→0、對照字串 1 個 1→1。

### 尚未完成

執行中的 App 載入的是 **`IntegratedApp.dist\NetRedirector.dll`**（既不是 repo 根目錄那份，
也不是 build 輸出那份），該檔被行程鎖住。要生效必須關閉 `IntegratedApp.exe` 後替換，
再重跑交錯 A/B 確認 A 臂回到 ~260–280 Mbps。

---

## 8. 證據等級

- **實測**：§1.1 延遲、§1.2 吞吐、§1.4 socket/防火牆、§2 三臂受控實驗、§5 端到端 A/B、§7 全部驗證。
- **讀碼確認**：§3 的機制與行號。
- **推論**：§2 的 BDP 算式是算術推導，不是量測值；「64 KB → ~210 Mbps」與實測 231/172 相符但非同一件事。
- **未經實測**：修復後的效能增益（等替換 DLL 後重跑 A/B）。

本次量測累計下載約 6–7 GB（走 Pad 的 5G）。

---

## 9. 修復過程中新發現

- **IPv6 代理位址無法設定**：`NetRedirector_AddProxyConfig` 與 `_SetProxyConfig` 都先過
  `resolve_hostname()`，而它 `hints.ai_family = AF_INET`（只收 IPv4）。
  所以 `build_windivert_filter()` 的 IPv6 排除分支目前**不可達**（保留為對稱防禦；
  測試改以直接寫 `g_proxy_ip` 全域來覆蓋該分支）。
- **可解析的主機名會被原樣存進 `proxy_ip`**（驗證通過後沒轉成 IP）。濾鏡語言沒有 DNS，
  所以這類端點會被安全跳過（記 warning），只是少了那次的加速。
- **`NR_Utils.c:679` 的 `is_ip_like_pattern` 隱式宣告是既有問題**（MSVC 只當警告，
  MinGW gcc 當 error），非本次改動造成，未動它。

---

## 10. 效能複查（第二輪，2026-09-27）：還有哪裡可以再提升

### 10.0 結論

1. **封包路徑已經沒有值得再動的地方。** 實測整個 `process_packet()` 熱路徑在
   280 Mbps（23 333 pps、1500-byte 幀）下只吃**單核 ~0.85%**，而且那是上限
   （假設每包都重算 checksum；§6 修完後只在真的改寫時才算）。**瓶頸是網路路徑，
   不是 CPU。** 任何封包路徑的微優化都不可能提高吞吐。
2. **新找到一個真正值得修的地方，而且不在封包路徑：**
   `GetExtendedTcpTable()` 每條新連線至少呼叫一次，實測 **~650 µs/次**，
   且是**固定成本**（與表大小無關）。這是全 repo 單價最高的操作，
   比整條封包路徑高 **5 個數量級**。它影響的是**連線建立延遲／網頁反應**，
   不是測速的 Mbps。
3. **已驗證 TCP socket 上不再有任何 `SO_RCVBUF`。** 全 repo 只剩 3 處，
   全部在 UDP socket（`NR_Protocol.c:254`、`NR_Core.c:993`、`NR_Core.c:1010`），
   那是正確且刻意的（UDP 沒有視窗自動調整可破壞，加大只是防丟包）。

### 10.1 負面結果（先講，避免白做工）

複查時識別出的每一項低效，都先量了單價才決定要不要動。**四項全部判定不值得修**：

| 項目 | 位置 | 實測單價 | 280 Mbps 下佔單核 | 判定 |
|---|---|---|---|---|
| TCP case 2 雙重 walk（`is_connection_tracked` + `get_connection`） | `NR_Core.c:223` | **25–46 ns/包** | 0.06–0.11% | 不值得 |
| UDP case 2 雙重 walk | `NR_Core.c:139` | 同上 | 同上 | 不值得 |
| 新連線路徑雙重 walk（miss 兩次全走訪） | `NR_Core.c` case 3 → `NR_RuleEngine.c:165` | **~1 µs/新連線**（512 條時） | 對比 650 µs 的 pid 查詢 = 0.15% | 不值得 |
| `WinDivertHelperParsePacket` 每包解析兩次（receiver + `process_packet`） | `NR_Core.c:473` + `:89` | 23 ns/包 | 0.05% | 不值得 |

**為什麼 case 2 的雙重 walk 幾乎免費**：`is_connection_tracked()` 自己也有 move-to-front，
所以它把命中的節點搬到表頭之後，緊接著的 `get_connection()` 是在表頭命中 —— 兩次呼叫
但只有一次全走訪。實測在 512 / 2048 條串列下都穩定在 25–46 ns，與串列長度無關。
**這是「看起來像問題、量了才發現不是問題」的典型案例。**

### 10.2 主要發現：新連線路徑被一個 650 µs 的系統呼叫支配

`tests/bench_conn_lookup.c`（連結**真實** `NR_State.c`，走訪含 critical section）：

```
System table snapshots (the whole table is copied out of the kernel):
  GetExtendedTcpTable  IPv4 OWNER_PID_ALL            649.8 us/op   (468 entries)
  GetExtendedUdpTable  IPv4 OWNER_PID                213.2 us/op   (242 entries)
  GetExtendedTcpTable  IPv6 OWNER_PID_ALL            640.8 us/op   (173 entries)

Where the 650 us goes:
  TCP_TABLE_BASIC_ALL  (no owner pid)                621.0 us/op  (468 rows)
  TCP_TABLE_OWNER_PID_CONNECTIONS                    475.0 us/op  (363 rows)
  TCP_TABLE_OWNER_PID_ALL                            649.8 us/op  (468 rows)
  user-mode rescan of an already-copied table          0.159 us/op (467 rows)
```

**兩個關鍵事實：**

- **成本幾乎全是固定開銷，不是逐列成本。** IPv4 468 列 = 650 µs，IPv6 173 列 = 641 µs
  —— 列數差 2.7 倍，時間幾乎一樣。owner-PID 解析只佔 4%（650 vs 621 µs）。
  所以**換更便宜的表類別沒有用**（`BASIC_ALL` 一樣 621 µs）。
- **每次查詢都是一次 miss。** `PID_RESULT_CACHE_SIZE 128` 的快取 key 含 `local_port`，
  而每條新連線的本地埠都是新的 —— 這個快取**對新連線的第一次查詢永遠不會命中**，
  它只能服務同一條連線的第二次查詢。

**而且失敗（pid == 0）不進快取**（`NR_Utils.c:80` 註解明寫「Failures (pid == 0) are NOT
cached」）。所以當 pid 解析不出來時，同一個 socket 會被快照兩次：

```
handle_new_connection_logic()  NR_RuleEngine.c:200-216  → 1 次
   └─ else 分支 → check_process_rule()  :250 → :99        → 再 1 次（miss，因為 pid 0 沒被存）
```

UDP 更糟：`get_process_id_from_udp_connection()` 失敗後還會回退查 TCP 表，
所以單一函式呼叫就是 UDP 表 + TCP 表兩次快照，而整條路徑會走兩遍 ——
**最壞情況 4 次快照 ≈ 1.6 ms**。

**影響**：一條新連線 = 650 µs（happy path）到 1.3 ms（pid 解析失敗）的序列成本。
一個開 100 條連線的網頁 = **65–130 ms 的純系統呼叫開銷**，而且它跑在 flow worker 上，
會讓同一條 flow 的封包排隊；若 worker 佇列滿導致 receiver 內聯處理，
還會**卡住整個封包接收管線**（head-of-line blocking）。

> **對應到原始症狀**：這解釋的是使用者說的「**網頁測速反應看起來遲鈍**」，
> **不是**測到 200 Mbps 那件事。吞吐天花板是 §2 的 `SO_RCVBUF`（已修）。

### 10.3 已驗證的修法：用 WinDivert SOCKET 層餵一個 pid map

`tests/probe_flow_layer.c` 證實這份 WinDivert（2022-09-20 build，DLL 47 616 bytes）
**支援 FLOW 層與 SOCKET 層**，而且事件裡直接帶 `ProcessId`：

```
--- NETWORK layer (control) (layer 0, flags 0x0) ---   OK
--- FLOW layer   (layer 2, flags 0x5) ---              OK
  event=1 pid=68552 proto=6 ports=54987->5228 L=[c0a801c8 0000ffff ...]
  event=1 pid=66280 proto=6 ports=33100->54987 L=[c0a801c8 0000ffff ...]
--- SOCKET layer (layer 3, flags 0x4) ---              OK
  event=7 pid=66280 proto=6 localport=53560 remoteport=1080 L=[c0a801c8 ...] R=[c0a801b2 ...]
```

**⚠️ 我第一版探針結論是錯的，必須記下來：** 我傳 `flags = 0`，得到
`ERROR_INVALID_PARAMETER (87)`，就寫下「此層不支援」。**這是錯的。**
`WinDivertOpen` 是**一起**驗證 filter / layer / priority / **flags** 的，
而官方文件給每層規定了強制 flags：

| 層 | 官方文件寫的強制 flags | 實測可用的 flags |
|---|---|---|
| `WINDIVERT_LAYER_FLOW` | `WINDIVERT_FLAG_SNIFF \| WINDIVERT_FLAG_RECV_ONLY`（0x5） | 0x5 ✅ |
| `WINDIVERT_LAYER_SOCKET` | `WINDIVERT_FLAG_RECV_ONLY`（0x4） | **0x4 會 wedget 全機 socket 建立，必須用 0x5** ⚠️ |

補上 flags 後兩層都正常開啟並收到事件。**教訓：`ERROR_INVALID_PARAMETER` 不能推論成
「不支援」，它同時涵蓋 flags 不合法。**

#### ⚠️ 最重要的一個發現：SOCKET 層缺 `SNIFF` 會讓**全機** socket 建立失敗

官方文件說 SOCKET 層要 `RECV_ONLY`，**照做會出大事**。實作後第一次跑對照測試時，
`pid_map_start()` 開著的期間**所有 `bind()` 都回 `WSAEACCES (10013)`**，
連測試自己的 listener 都建不起來 —— 也就是說這個 handle 會干擾**整台機器**的 socket 建立，
不只是中繼自己。`tests/probe_socket_layer_safety.c` 四組對照隔離出來的結果：

```
SOCKET layer, RECV_ONLY            :  0/12 bound    first: bind() wsa=10013
SOCKET layer, SNIFF|RECV_ONLY      : 12/12 bound
FLOW   layer, SNIFF|RECV_ONLY      : 12/12 bound
NETWORK layer (control)            : 12/12 bound
(after close = 12/12，效果完全可逆)
```

**根因**：`WINDIVERT_FLAG_SNIFF` 才是讓 SOCKET 層變成 observational 的旗標；
少了它，驅動會試圖對 socket 事件「負責」（含 ALE 授權路徑），於是擋掉了建立。
→ 實作上 `PID_MAP_LAYER_FLAGS` 硬性定為 `WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY`，
並在 `NR_PidMap.c` 留長註解記錄這組實測數據，防止後人「照文件」把它改回 0x4。

**實測到的欄位編碼**（不靠猜，直接 dump 原始欄位讀出來的）：

- **埠是 host byte order**：`RemotePort` 原始值就是 `443`（若為網路序，443 = 0x01BB
  在小端讀出會是 47873）。→ 實作時**不要**再 `ntohs()`。
- **IPv4 位址在 `LocalAddr[0]`，且是網路序的 UINT32**：`0xc0a801c8` = `192.168.1.200`，
  可直接丟給 `inet_ntoa`；`LocalAddr[1] = 0x0000ffff` 是 v4-mapped 標記。
- 事件型別：SOCKET 層 `3=BIND 4=CONNECT 5=LISTEN 6=ACCEPT 7=CLOSE`；
  FLOW 層 `1=ESTABLISHED 2=DELETED`。

**為什麼該選 SOCKET 層而不是 FLOW 層**：中繼必須在**第一個封包**上就決定路由。
`SOCKET_BIND` / `SOCKET_CONNECT` 是在 socket API 路徑上產生的，早於封包送出；
`FLOW_ESTABLISHED` 是 flow 建立時（UDP 是第一個 datagram 才建立），與封包同時，
競態窗口更大。

**已實作的設計**（`NR_PidMap.h` / `NR_PidMap.c`，2026-09-27 完成）：

1. 開一個 `WINDIVERT_LAYER_SOCKET` handle，一條事件執行緒維護
   `(proto, local_port) → pid` 的 hash map（4096 槽、8 格 probe window、
   TTL 3000 ms、`WinDivertRecv` timeout 1000 ms）；
   `BIND`(3) / `CONNECT`(4) / `ACCEPT`(6) 插入，`CLOSE`(7) 移除，其餘事件計數後忽略。
   hash 只依 `(proto, port)`、**不依位址** —— 讓同埠的不同 socket 落在同一個 probe
   window 裡，才能偵測到 ambiguity。
2. `get_process_id_from_connection[_udp]()` **先查 map**；
   **miss 才回退** `GetExtendedTcpTable`。
   → 命中時 650 µs → ~0.1 µs；
   → 競態時行為**與今天完全相同**，不會有正確性回歸。
   刻意**不把 map 的答案寫進 `PID_RESULT_CACHE`** —— 那會讓 map 的答案活得比 map 自己的
   TTL 更久，等於繞過 map 用來界定陳舊度的機制（`NR_Utils.c` 四個插入點都有註解說明）。
3. map 要**排除中繼自己的 pid**（`g_current_process_id`）—— 探針已證實中繼自己的通道
   （`ports=33100->54987`）也會出現在事件流裡。
4. **fail closed**：同一 `(proto, port)` 出現兩個不同 pid 時，該槽標記 `ambiguous=1`
   並**停止作答**（回 miss，讓呼叫端走權威表）。`pid_map_lookup()` 掃完 probe window
   全 8 格、**不做 early termination**，就是為了不漏掉 ambiguity 標記。
   `pid_map_remove()` 也只在 pid 相符時才清 —— 避免遲到的 `CLOSE` 誤刪已被回收埠的新 socket。
5. 生命週期上它是**可選加速器，不得讓 `NetRedirector_Start()` 失敗**：
   `pid_map_start()` 開 handle 失敗只記 log 並回 `FALSE`，主流程照走（此時所有查詢都走
   權威表，等於回到修正前行為）。`fail:` 區塊與 `NetRedirector_Stop()` 各呼叫
   `pid_map_stop()`，Stop 時輸出命中率統計。

#### 動手前的驗證閘門：已通過（不一致率 = 0）

動手前我對 map 的可信度存疑（探針裡有幾筆 `pid=4` System 事件，且 `EndpointId` 在多筆不同
4-tuple 上重複出現，其中一筆正是連往代理 `192.168.1.178:1080` 的連線），所以先立了閘門：
**對 N 條 flow 同時用 map 與 `GetExtendedTcpTable` 解析，不一致率必須是 0。**

`tests/probe_pid_map.c` 驅動**真實的 `pid_map_start()`**（不是複製品），分兩段：

- **A 段（安全性）**：handle 開著時連續建立/回收 listener，延遲 ratio 跨四次量測為
  `1.59 / 0.72 / 1.20 / 0.92` —— 全部落在雜訊內，沒有系統性劣化。
- **B 段（正確性）**：每 cycle 重建 listener 並 `accept()` 回收，逐筆與權威表比對：

```
TCP : 24/24 一致
UDP : 16/16 一致
CONFLICT (map 與權威表給出不同 pid): 0
lookups=40  hits=40  (100%)
```

**閘門通過，`CONFLICT = 0`** —— 上面那幾筆可疑事件沒有污染答案（`pid=4` 那類事件會落在
`ignored_events` 或因為不是 BIND/CONNECT/ACCEPT 而被丟掉，不會進 map）。
閘門的價值在於：它是一個**能證偽的判準**，而不是「看起來對了」。
如果哪天驅動行為改變導致 conflict，`ambiguous` 機制會自動把它降級成 miss（fail closed），
行為退回修正前，不會給出錯誤的 pid。

### 10.4 證據等級

- **實測**：§10.1 全部單價、§10.2 全部快照與串列數據、§10.3 探針輸出與欄位編碼、
  SOCKET 層四組安全性對照、map 與權威表 40/40 一致（CONFLICT 0）。
  基準／探針程式：`tests/bench_packet_helpers.c`、`tests/bench_conn_lookup.c`（連結真實
  `NR_State.c`）、`tests/probe_flow_layer.c`、`tests/probe_socket_layer_safety.c`、
  `tests/probe_pid_map.c`。
- **讀碼確認**：§10.1 的行號、§10.2 的「pid 0 不進快取」與呼叫鏈、§10.3 的四個插入點
  （`NR_Utils.c:791 / 820 / 852 / 879`）與三個生命週期插入點
  （`NetRedirector.c:835 / 893 / 955`）。
- **推論**：「100 條連線 = 65–130 ms」是 650 µs × 100 的算術，**未經端到端量測**；
  「會卡住接收管線」是依 `dispatch_packet` 佇列滿時內聯處理的程式結構推得，未實測。
- **已驗證可運作，但增益未量測**：map 的 pid 正確性（§10.3 末，閘門已通過）；
  `build.ps1` 建置成功、C 測試 **222/222 通過**、符號配對證明新程式碼確實在 DLL 裡
  （新字串 `PID map: socket-event cache up` 等 0→1，對照字串 1→1，
  DLL md5 `a295fdeb…` → `568ecaf3…`；§10.6 補上前置宣告後重建為 `7ad5492e…`，
  222/222 再次通過）。
- **未驗證**：**端到端增益**（命中率 × 650 µs 的實際省下多少）尚未量測。
  要量它需要：把新 DLL 換進 `IntegratedApp.dist\`、重啟 App、跑一輪會開大量連線的
  網頁測速，然後讀 Stop 時的 `PID map: N/M process lookups served from socket events (X%)`。
  在那之前，「新連線延遲改善」屬於**推論**而非實測。

### 10.5 仍未解的問題（下次要動的話從這裡開始）

1. **`get_process_id_from_udp_connection()` 失敗後回退查 TCP 表**（`NR_Utils.c`）：
   單次呼叫就是 UDP + TCP 兩次快照（213 + 650 µs），且整條路徑會走兩遍，
   最壞 ≈ 1.6 ms。map 命中時已繞過，但 miss 時仍在。
   **可考慮**：讓「pid 0 的失敗結果」進快取（短 TTL），把 4 次快照壓成 1 次。
   我沒動它，因為那會改變「失敗不快取」這條既有契約，需要先確認當初為什麼這樣寫。
2. **`process_packet()` 仍無測試覆蓋**（static、難注入）。
   §10.1 的四項「不值得修」是靠量測排除的，但如果哪天有人改了它，
   沒有回歸網可以擋。要補的話得先把封包解析/改寫那段抽成可測的純函式。
3. **`PID_RESULT_CACHE` 的 key 含 `local_port`**，導致它對新連線的第一次查詢永不命中。
   這不是 bug（設計如此），但它意味著那個快取在「每條連線只查一次」的場景下幾乎沒用。
   若日後有實際 profile 顯示它常命中，再回來檢討。

### 10.6 第三輪複查（2026-09-27）：最後一個候選項也被量測否證

map 上線後，快路上只剩一個還沒量過的東西：`pid_result_cache_lookup()` 是
**128 格的線性掃描**，而且它在 map 之前被呼叫 —— 所以它對**每一次** pid 查詢都要跑一遍，
包括 map 存在的意義所在（新連線的第一次查詢）。如果它比它前面的 map 探測還貴，
那它就變成快路的實際瓶頸。

**假設：128 格線性掃描會主導快路徑。→ 量測結果：否證。**

`tests/bench_pid_cache.c` 連結**真實** `NR_Utils.c`，在 127.0.0.1 上開 128 個 listener
把快取灌滿（store 路徑是 round-robin，所以 `ports[i]` 一定落在第 `i` 格），
於是「命中第 i 格」就直接等於「掃 i+1 格」——**完全不需要減去任何 baseline**：

```
2. cache HIT cost by slot position (128 live entries):
     slot   0 (scans   1 slots)     0.024 us
     slot  31 (scans  32 slots)     0.036 us
     slot  63 (scans  64 slots)     0.066 us
     slot 127 (scans 128 slots)     0.113 us
     -> marginal scan cost  (slot127 - slot0) = 0.090 us for 127 slots  = 0.71 ns/slot
     -> a FULL 128-slot miss therefore costs ~0.113 us
```

**0.71 ns/格，滿載 128 格 ≈ 0.11 µs。** 而且「空快取 vs 滿快取的全 miss」差值是
`−61.5 µs`，同時 baseline 自己的兩次取樣差值是 `−117.8 µs` ——
**掃描成本比它前面的表快照自身的雜訊還小 3 個數量級**，在同一支程式裡根本解析不出來。

**結論：不值得改。** 三個推論：
- 把快取改成 hash 只為了省 0.11 µs，對比它省下的 650–1000 µs 是 0.01%，**投入與風險都不合理**。
- 也不能用「把 map 提到快取前面」來省它：那會改變兩者的優先序語意（快取的 key 帶位址、
  更精確），換來 0.11 µs，不划算。
- 這與 §10.1 的四項同一類：**看起來像問題，量了才知道不是問題。**

**順手修掉的既有缺陷**：`NR_Utils.c` 的 `is_ip_like_pattern()` 在 693 行被呼叫、
1144 行才定義，先前沒有前置宣告。MSVC 只給警告，**gcc 把
「static declaration follows non-static declaration」當成 error**，
使得任何想用 gcc 連結 `NR_Utils.c` 的基準程式都編不起來（本節的 bench 就是第一個）。
已補上前置宣告，語意不變；MSVC 建置與 222 項 C 測試重跑全過。

---

## 11. 兩個與吞吐無關、但有證據的觀察（2026-09-27）

這一節刻意獨立於 §1–§10：前者講 Mbps，這裡講的是另外兩件事，
**它們都還沒被修，也都不確定該不該修** —— 先記錄證據，不先動手。

### 11.1 關機固定慢 1.1 秒（已量測，可重現）

`IntegratedApp.py` 自己在 `_perform_shutdown()` 裡逐段計時寫 `shutdown_timing.log`。
兩次不同日期的執行：

```
(root, 09-23)                          (IntegratedApp.dist, 09-27)
save_config:          3 ms             save_config:          5 ms
monitor_thread.stop: 52 ms             monitor_thread.stop: 12 ms
bridge.stop:       1107 ms             bridge.stop:       1117 ms   <-- 固定
server.stop_all:    332 ms             server.stop_all:      0 ms
```

`bridge.stop()` 就是 `NetRedirector.py` 的 `NetRedirectorWrapper.stop()`，
內容只有一行 `self.lib.NetRedirector_Stop()`。所以 1.1 秒花在 DLL 的
`NetRedirector_Stop()` 裡。該函式依序 join 了：packet threads（5 s timeout）、
proxy thread、udp relay thread、cleanup thread、DNS refresher —— 全部是 5 秒上限，
而實際只花了 1.1 秒，所以**沒有任何一個 join 逾時**，是某個執行緒真的花了大約 1 秒才退出。

`1117 ms ≈ 1000 ms + 117 ms` 這個形狀指向某處有一個 1 秒的等待
（`Sleep(1000)` 或 1000 ms 的 wait timeout）。**但我沒有去追是哪一個 —— 這是推論，不是實測。**
影響：只在關閉程式時發生一次，與吞吐、與「網頁反應遲鈍」都無關。
要不要修取決於使用者覺得這 1.1 秒值不值得動。

### 11.2 殘餘的 200 vs 300 Mbps：PC↔Pad 那段已經被量過，不是瓶頸

**⚠️ 我先寫下了一個「手機的 Wi-Fi 段是瓶頸」的假設，然後發現它早就被實測推翻了。**
記錄下來，因為它正是「聽起來合理 ≠ 成立」的典型：

- **假設**：手機自己測到 300+ 是手機→5G，不經 Wi-Fi；電腦走的路徑多了一趟
  手機↔路由器的 Wi-Fi，所以 200 是物理上限。這台電腦是有線的（`netsh` 只有
  「乙太網路」，無任何無線介面），聽起來完全說得通。
- **但它已經被量過，而且答案是「不成立」**：用本地 HiNet
  （`http://http.speed.hinet.net/test_1024m.zip`，該 host 只有 http 有回應）
  ＋ `curl --max-time 8` 截斷量穩態，**PC → Pad SOCKS5 單線實測
  239.5 / 277.5 / 290.9 / 268 / 285 / 279 Mbps** —— 也就是說
  「5G → 手機 → Wi-Fi → 路由器 → 有線 → 電腦」這整條路徑**本身可以跑到 ~280–290**。
  Wi-Fi 那一段不是瓶頸。

**而且更早還有一層更正值得記**：第一次用 Cloudflare / Vultr 東京測得 82 Mbps，
就下過「主因在 Wi-Fi」的結論 —— **那也是錯的**，是**測速來源自己在限速**。
教訓：**先驗證測速來源本身的天花板，再拿它的數字推論路徑能力。**

**所以真正的主因是 `SO_RCVBUF`（§2），已修。而這一節剩下的唯一未驗證項目是：
修完之後，端到端是否真的回到 ~280 Mbps。** 這需要一次 A/B（見 §7「尚未完成」）。
在那之前不要對殘餘落差再編故事 —— 先量。

---

## 12. 發行後端到端複測（2026-09-27，v1.8.2 已發行）

本報告最後留下的未驗證項目（「修完之後，端到端是否真的回到 ~280 Mbps」）已補測完成。

**受測對象**：`IntegratedApp.dist\NetRedirector.dll`，md5 `E0E4EE1E…`，與 repo 根目錄、
`NetRedirector\` 兩份完全相同，且位元組比對含全部新字串（`udp passthrough`、`tcp unchanged`、
`proxy endpoint(s) from capture`、`process lookups served from socket events`）
→ 18:52 啟動的 App 跑的就是修好的引擎，**不必關 App、不必重啟**即可量測。
防火牆規則恰好 2 條也是佐證。

**吞吐（交錯 6 輪 × 6 s + 暖機，`ab_measure.py`）**

| 臂 | median | min | max | avg |
|---|---|---|---|---|
| A 中繼（本機 33100） | **254.6 Mbps** | 226.5 | 272.1 | 252.8 |
| B 直通（`curl -x socks5h://192.168.1.178:1080`） | 261.0 | — | — | 249.4 |

A/B = **0.976**。對照 §5 修正前 A 臂的 182.7–197.5 Mbps（天花板 ~210 Mbps），
本輪 max 272.1 Mbps **越過舊天花板** → 天花板解除，該未驗證項目結案。

**新連線延遲歸因（15 對，`ab_latency.py`，中位數 ms）**

| 階段 | A 中繼 | B 直通 | 差 |
|---|---|---|---|
| DNS | 9.46 | 0.04 | +9.42 |
| connect | 11.58 | 5.57 | −3.40 |
| 請求／回應 | 76.57 | 66.69 | +3.87 |
| 合計 | 76.70 | 66.75 | +9.95 |

DNS 的 +9.42 ms 是 `g_dns_via_proxy = TRUE` 的設計行為；connect 反而快 3.4 ms
（中繼在本機就完成交握）。扣掉兩者後**引擎自身每條新連線只加約 4 ms** ——
§10.2 的 650 µs pid 查詢只是其中一小部分，**不是延遲主因**。
（證據等級：已量測。）

**pid 快取命中率（實機累積約 1 小時 42 分，真實流量）**

```
[DLL] PID map: 15541/23554 process lookups served from socket events (66.0%), 2473 ambiguous, 235199 events consumed
```

命中率 66.0%；`ambiguous` 2473 次即 §10.3 fail-closed 設計的實際觸發次數。
另 log 顯示 `PID map: socket-event cache up (layer=SOCKET, ttl=3000 ms)`。

**其他現場證據**：防火牆規則 118 → 2 條（§6 第 5 項的現場驗證）；
log 顯示 `excluding 8 proxy endpoint(s) from capture`（§6 第 2 項生效）。

> 方法備註：引擎 log 只進 GUI 的 `txt_log`（`IntegratedApp.py` 的 `append_log`），
> **不落檔**；而該 Qt 視窗被縮到系統匣時不會重繪，`PrintWindow` 也拿不到內容。
> 本次流程是：以 `WM_MOUSEWHEEL` 定點滾動 + `PrintWindow(PW_RENDERFULLCONTENT)` 取像，
> 最後用「點進日誌區 → Ctrl+A → Ctrl+C → 讀剪貼簿」取得精確文字（免 OCR）。






