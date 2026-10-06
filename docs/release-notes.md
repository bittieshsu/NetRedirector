# NetRedirector v1.8.4

## 修正 v1.8.3 引入的 UDP 迴歸：遊戲「選完地圖進不去房間」

這一版只有一個主題：**把 v1.8.3 那筆「UDP 中繼穩健性」造成的迴歸修掉。**
受影響的是所有走代理的 UDP 遊戲與串流 —— 症狀不是變慢，是**整條 UDP 路徑在關鍵時刻斷掉**。

> 如果你是從 v1.8.3 升上來、而且玩連線遊戲，這一版務必更新。

---

## 一、症狀

Steam《鬥陣特攻》：進入房間、選完地圖之後**進不去遊戲**，連續三次失敗；
把版本退回 **1.8.0** 就完全正常。

## 二、根因

v1.8.3 的 `fix(udp): UDP 中繼穩健性` 同時加了三件事。每一件單看都有道理，
但其中兩件會把**暫時性錯誤升級成持續斷線**：

| # | v1.8.3 的改動 | 當初的理由 | 實際後果 |
|---|---|---|---|
| 1 | `sendto` 失敗就 `udp_assoc_drop()` | 「relay 死了、但 TCP 控制 socket 還沒偵測到」 | **不看錯誤碼**。阻塞式 UDP `sendto` 在爆量時回的是 `WSAENOBUFS (10055)` 這類**可重試**的錯誤 → 丟掉一個封包就拆掉整條 association |
| 2 | 每代理指數退避 2 s → 30 s | 「死代理不該讓每個 datagram 都付一次逾時」 | **一次**失敗就開窗；窗口內該代理**所有** datagram 被靜默丟棄，而且棘輪到 30 秒 |
| 3 | `UDP_ASSOC_TIMEOUT_MS` 10 s → 3 s | 「死代理能卡住所有人的時間」 | 重撥更容易失敗 → 更容易把退避棘輪鎖上 |

### 為什麼第 1 點特別致命：association 是「每代理一條」

`UDP_ASSOCIATION` 以 `proxy_id` 為 key，**一條吃下該代理全部的 UDP flow**。
所以「拆掉一條 association」不是掉一個封包，是**該代理所有 UDP 一起斷**。

進房間、選地圖那一刻正是 UDP 突發（地圖載入、玩家名單）。一次 `sendto` 錯誤就足以拆掉
association，接著退避把 UDP 鎖死數十秒 → 遊戲連線逾時、被踢回大廳。連續三次失敗，是因為
退避一旦棘輪上去，短時間內的重試全都落在窗口裡。

v1.8.0 兩者都沒有：`sendto` 失敗只記一行日誌、association 留著，下一個 datagram 就恢復
—— 毫秒級自癒。這就是「退回 1.8.0 就能玩」的原因。

## 三、修正

| 項目 | v1.8.3 | v1.8.4 |
|---|---|---|
| `sendto` 失敗 | **立刻**拆掉 association | 累計 `send_fail_streak`，**連續 100 次**才拆；成功即歸零 |
| 退避開窗條件 | 失敗 **1** 次 | 連續失敗 **2** 次（`UDP_ASSOC_BACKOFF_MIN_FAILS`） |
| 退避窗口 | 2 s 起、上限 **30 s** | 500 ms 起、上限 **5 s** |
| ASSOCIATE 逾時 | 3 s | **8 s** |
| 退避期間丟包 | **完全靜默** | 進入窗口、以及**首次** sendto 失敗都會記日誌 |

真 zombie（relay 真的死了）仍會被及時回收 —— 靠的是既有的「TCP 控制 socket 讀到 EOF」
那條路徑，不需要靠 `sendto` 失敗去猜。

**刻意保留不動**的三項 v1.8.3 改動（它們是對的）：`SIO_UDP_CONNRESET` 逐 socket 關閉、
以 `FIONREAD` 在單輪 `select()` 內排空、以及只在真的改寫過欄位時才重算 checksum。

## 四、怎麼確認修好了

實機驗證：更新到 1.8.4 後進入《鬥陣特攻》房間、選地圖、進遊戲，**連續多次正常**。

若之後又遇到同類症狀，日誌裡的**錯誤碼**可以直接判別機制：

| 錯誤碼 | 意義 |
|---|---|
| `10055` (WSAENOBUFS) | 爆量／緩衝耗盡 —— 就是這次修的機制 |
| `10051` / `10065` | 路徑斷（上游真的掛了） |
| `10054` | ICMP 未達（已在 association socket 上關閉通知） |

## 測試

- **C 測試套件 243/243 通過**（`NetRedirector/tests/run_tests.ps1`）。
- **Python：`pytest` 165 passed**。
- **符號配對**（版本號沒動，所以用字串證明新碼真的進了 DLL）：
  新字串 `retry held for the backoff window` / `retrying on the next datagram` /
  `keeping association` / `times in a row, last error=` 各 **0 → 2**（IPv4 與 IPv6 兩支），
  被刪掉的 `- backing off` **2 → 0**。

## 升級方式

使用內建自動更新即可。若更新流程本身有問題，直接下載本頁 zip 手動覆蓋
（`NetRedirector.dll` 必須與執行檔同目錄）。
