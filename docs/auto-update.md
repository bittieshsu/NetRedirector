# 自動更新機制實作指南（含踩坑紀錄）

> 適用於 **Windows + Python + Nuitka/PyInstaller 打包**的桌面應用程式。
> 本文件整理自 NetRedirector 專案實作自動更新的完整歷程，包含所有踩過的坑與最終解法。
> 其他專案若要實作類似機制，直接照這份來，就不用再重走一遍冤枉路。

---

## 一、整體架構

```
[發佈端]
  手動遞增版本號 → 打 git tag（例 v1.7.0）→ push
    ↓ CI 自動
  改寫 version.py 的版本號 → 打包 zip → 產生 SHA256SUMS.txt → 建立 GitHub Release
        ↓
[用戶端 App]
  「檢查更新」→ 查 GitHub Release API → 比對版本
    → 有新版本 → 下載 zip → SHA-256 校驗 → 解壓到旁路目錄
    → 啟動背景替換腳本（等主程式退出 → 交換資料夾 → 保留設定檔 → 重啟）
```

核心設計原則：

1. **版本號單一來源**（`version.py`，CI 用 tag 覆寫）。
2. **下載的二進位檔強制 SHA-256 校驗**，否則不套用（防供應鏈攻擊）。
3. **原子替換**：先下載到旁路目錄，交換失敗可回滾，不留半套狀態。
4. **執行期資料必須跨版本保留**（設定檔、歷史記錄等）。
5. **凍結偵測與 exe 路徑必須針對打包器各自處理**（見第五節，這是踩坑重災區）。

---

## 二、版本管理：單一來源

建立 `version.py`：

```python
APP_VERSION = "1.6.4"                 # 唯一版本來源，發佈前手動遞增
GITHUB_REPO = "yourname/yourproject"  # release API 用
UPDATE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
```

發佈流程（固定不變）：

1. 手動把 `version.py` 的 `APP_VERSION` 遞增。
2. 打跟它一致的 git tag（`v1.6.5`）。
3. push，CI 自動把 tag 版本寫回 `version.py` 再編譯進 exe（避免手動改兩處）。

---

## 三、發佈端（CI）

用 tag 觸發獨立 workflow（`.github/workflows/release.yml`）：

```yaml
on:
  push:
    tags: ['v*']

permissions:
  contents: write
```

關鍵步驟：

1. **把 tag 版本注入 `version.py`**（Nuitka 會把這值編譯進 exe）：
   ```powershell
   $v = $env:GITHUB_REF_NAME -replace '^v',''
   $raw = (Get-Content version.py -Raw) -replace 'APP_VERSION\s*=\s*"[^"]*"',
            ('APP_VERSION = "' + $v + '"')
   Set-Content version.py -Value $raw -NoNewline -Encoding utf8
   ```
   這一步很重要：因為 `version.py` 是常數字面量，Nuitka 編譯時會把它「凍」進二進位檔；若用 `os.environ` 讀版本，使用者端執行時不會有那個環境變數，版本會跑掉。

2. **打包 zip**：把 standalone 產出的 `.dist` 資料夾**內容**（不帶外層資料夾）壓成 `App-vX.Y.Z-win64.zip`。

3. **產生 SHA256SUMS.txt**：
   ```powershell
   $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
   "$hash  $zip" | Set-Content SHA256SUMS.txt -Encoding ascii
   ```

4. **建立 Release**：`gh release create $TAG $zip SHA256SUMS.txt --generate-notes`。

---

## 四、用戶端流程

### 4.1 檢查更新

```python
def check_update(current_version):
    release = requests.get(UPDATE_API_URL, timeout=15).json()
    latest = release["tag_name"].lstrip("v")
    if not _is_newer(latest, current_version):
        return None                      # 已是最新
    zip_asset = find_asset(release, ".zip")
    checksum_asset = find_asset(release, "sha256sums.txt")
    return { "version": latest, "url": ..., "checksum_url": ..., ... }
```

> 版本比較要用**整數 tuple**，不要用字串比對：字串比對會誤判 `1.10.0 < 1.9.0`。

### 4.2 下載 + 校驗 + 解壓

```python
def stage_update(url, name, checksum_url, progress_cb=None, cancel_event=None):
    expected = parse_sha256(checksum_url, name)   # 從 SHA256SUMS 解析出本資產的雜湊
    download_file(url, tmp, progress_cb=progress_cb, cancel_event=cancel_event)
    if not verify_sha256(tmp, expected):
        raise RuntimeError("SHA256 校驗失敗，中止")
    extract(tmp, dist_dir + ".new")               # 解壓到旁路目錄
    # 解壓前做 zip-slip 防護：確認每個條目的目標路徑都在 new_dir 內
```

**下載採多線程分段（`download_file`）**，因為 GitHub release 資產在部分網路
環境單線只有數十 KB/s，34 MB 要十幾分鐘，看起來像卡死：

1. **路徑選擇（智能分流）**：先並行實測「直連 + `config.json` 內每一條代理」
   的實際吞吐（各抓 256 KB 真實資料計速，不是只量 ping），挑最快的一條下載。
   代理連不上、不支援或中途失敗都會自動改用次快的路徑，最後保底直連；
   沒有任何代理時完全不量測，零額外延遲（詳見 4.4 與坑 13）。
2. 以 `Range: bytes=0-0` 探測檔案大小與是否支援分段，並記下轉址後的簽名
   CDN URL（讓所有分段共用，省去每段重走一次 302）。
3. 切成多段並行下載（分段目標 1 MB，上限 32 段；連線數隨檔案大小提升）。
4. **進度回報**：`progress_cb` 每 0.5 秒收到 `{downloaded, total, speed, threads}`，
   UI 以 `QProgressDialog` 顯示並提供取消。速度取**數秒滑動視窗平均**，
   不可用瞬時值（見坑 13）。
5. **停滯偵測**：30 秒視窗內收到不足 128 KB 即判定該段卡住，中斷後重試
   （每段最多 4 次），避免慢速滴流無限等待。
6. **後備路徑**：伺服器不支援 Range 或分段失敗時，自動退回單線串流重試。
7. 每次啟動更新前清掉 `%TEMP%\netredir_update_*.zip` 殘檔（舊版每次重試都留一個）。

> 逾時要用**讀取逾時**而非總時間：慢速但持續有資料的連線不會觸發 per-read
> 逾時，必須靠停滯偵測（視窗內位元組數）才能判斷「卡住」。

### 4.4 路徑選擇（智能分流 + 防呆）

實作在 `updater.py` 的 `load_proxy_urls()` / `_measure_path()` /
`_rank_download_paths()` / `download_file()`：

- **候選**：直連 + `config.json` 的 `proxies` 清單（SOCKS5 / HTTP）。
  VPN Gate 那些是 SoftEther 虛擬網卡、不是 SOCKS 代理，不會進入候選。
- **量測**：每條路徑各發一次 256 KB 的 Range 請求實測吞吐後排序，取最快者下載。
  量的是**相對快慢**；實際下載會用多條並行連線，所以排名不等於最終速率。
- **防呆**：個別路徑失敗只會少一個候選；直連永遠保留且保底排最後；
  `config.json` 不存在／損毀／非 JSON 一律視為無代理，不拋例外、不中斷更新。
- **SOCKS5 用 `socks5h://`**：由代理端解析 DNS，避免本機 DNS 被轉址規則影響。
  密碼沿用 `secure_config` 的 DPAPI 解密，解不開就當無密碼。
- **可觀測性**：選路與換線結果寫入主視窗日誌，例如
  `更新下載路徑: MyPhone (0.22 MB/s)`、`路徑「X」失敗，改用下一條: ...`。

### 4.3 原子替換 + 重啟

由背景 PowerShell 腳本執行（主程式此時已自行關閉）：

1. 等主程式程序真的退出（`Get-Process -Name <exe名>`）。
2. 交換：`dist` → `dist.old`、`dist.new` → `dist`（帶重試，處理檔案解鎖延遲）。
3. **把執行期資料從 `dist.old` 搬回 `dist`**（`config.json`、歷史檔等）——不做這步設定就會被清零。
4. 用 .NET `ProcessStartInfo`（`UseShellExecute = $false`，走 CreateProcess）重啟。
5. 清理 `dist.old`（同步重試）。

---

## 五、踩坑紀錄（最重要的一節）

### 坑 1：Nuitka 不設 `sys.frozen`

- **現象**：打包後程式仍被誤判成「原始碼模式」，自動更新的套用步驟被擋。
- **根因**：`sys.frozen` 是 PyInstaller / cx_Freeze 的慣例；**Nuitka 是注入模組全域變數 `__compiled__ = True`**，不設 `sys.frozen`。
- **解法**：凍結偵測要同時涵蓋三種打包器：

```python
def is_frozen():
    if getattr(sys, "frozen", False):          # PyInstaller / cx_Freeze
        return True
    if hasattr(sys, "_MEIPASS"):               # PyInstaller onefile
        return True
    if globals().get("__compiled__", False):   # Nuitka
        return True
    return False
```

> 注意 `globals()` 在函式內指的是「定義該函式的模組」的 dict，所以 `globals().get("__compiled__")` 要寫在被 Nuitka 編譯的那個模組裡才有效。

### 坑 2：Nuitka 的 `sys.executable` 指向內建 `python.exe`（本專案最痛的一坑）

- **現象**：更新後「只關閉、不重啟」。查 log 發現 `Exe=[...\python.exe] ExeName=[python]`、`swap ok=False`。
- **根因**：Nuitka standalone 會把 `sys.executable` 設成 **dist 內建的 `python.exe`**，而不是真正的 `IntegratedApp.exe`。於是 exe 名稱被算成「python」，替換腳本去等「python」程序退出——但真正在跑的是 `IntegratedApp`，等錯對象 → 太早去交換資料夾 → 資料夾被執行中的程式鎖住 → 交換失敗 → 跳過重啟。
- **解法**：**用 `sys.argv[0]` 取得真正的 exe**，失敗才回退 `sys.executable`：

```python
def _frozen_exe_path():
    argv0 = sys.argv[0] if sys.argv else ""
    p = os.path.abspath(argv0) if argv0 else ""
    if p and p.lower().endswith(".exe"):
        return p
    return os.path.abspath(sys.executable)
```

`current_dist_dir()` 與 exe 名稱（`Get-Process` 用的）都要從這個 helper 來，**不要直接信任 `sys.executable`**。

### 坑 3：PowerShell 5.1 的 `Start-Process` 沒有 `-UseShellExecute`，預設 ShellExecute 會卡住

- **現象**：背景替換腳本在重啟那一步拋「找不到符合參數名稱 'UseShellExecute' 的參數」；若改用預設 ShellExecute，又會卡住超過 2 分鐘（沙盒實測）。
- **根因**：`-UseShellExecute` 是 **PowerShell 7+（Core）才有的參數**；Windows PowerShell 5.1 的 `Start-Process` 沒有這個參數，而且預設走 ShellExecute，遇到無效 exe 或特定 manifest 會彈對話框或直接卡住。
- **解法**：改用 .NET `ProcessStartInfo` 設定 `UseShellExecute = $false`（走 CreateProcess，跨 PS 5.1 / 7 行為一致）：

```powershell
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Exe
$psi.WorkingDirectory = $Dist
$psi.UseShellExecute = $false   # 走 CreateProcess，不經 ShellExecute
[System.Diagnostics.Process]::Start($psi) | Out-Null
```

> ⚠️ 不要寫 `Start-Process -UseShellExecute $false`：該參數在 PS 5.1 不存在，會直接拋參數綁定錯誤。

### 坑 4：PowerShell 5.1 讀無 BOM 的 UTF-8 會亂碼

- **現象**：腳本內的中文註解亂碼，甚至影響解析。
- **根因**：無 BOM 的 `.ps1` 會被 PS 5.1 用系統 ANSI 字碼頁讀取，UTF-8 中文變成亂碼。
- **解法**：二選一——
  1. 產生 `.ps1` 時用 `open(path, "w", encoding="utf-8-sig")`（加 BOM）；
  2. 更保險：**腳本內容保持全 ASCII**（註解用英文），從源頭排除編碼問題。

### 坑 5：日誌路徑別依賴 `$env:TEMP`，也別放在 try 外面

- **現象**：重啟失敗，但想看的日誌完全沒寫出來，無從偵錯。
- **根因**：`$logPath = Join-Path $env:TEMP ...` 寫在 `try/catch` **外面**；一旦 `$env:TEMP` 異常或 Join-Path 拋錯，腳本直接終止、不留任何痕跡。
- **解法**：
  1. 日誌路徑由 **Python 端當參數傳入**（明確、可預期），不要讓腳本自己拼 `$env:TEMP`。
  2. 逐步記錄（start / app exited / swap / config / restart / cleanup），每步都寫。
  3. 把 powershell 的 stderr 另外導到檔案，捕捉解析/執行錯誤。

### 坑 6：`Start-Job` 會卡住 stdout/stderr 管道

- **現象**：用 `subprocess.run(capture_output=True)` 跑替換腳本時永遠不返回。
- **根因**：`Start-Job` 會 spawn 一個孫程序 powershell，它**繼承了 stdout/stderr 管道**，父程序等不到 EOF。
- **解法**：背景清理別用 `Start-Job`，改成**同步重試**：

```powershell
for ($i = 0; $i -lt 10 -and -not $cleaned; $i++) {
    Remove-Item $OldDir -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $OldDir)) { $cleaned = $true } else { Start-Sleep -Seconds 1 }
}
```

### 坑 7：資料夾交換會把設定檔一起刪掉

- **現象**：更新成功但使用者設定全部歸零。
- **根因**：程式把 `config.json` 寫在執行檔同目錄（`.dist` 內），而「原子替換」是整個資料夾改名交換，所以設定檔跟著舊資料夾一起被丟。
- **解法**：交換完成後，把「執行期資料清單」從舊資料夾複製回新資料夾（在重啟之前）：

```powershell
foreach ($f in @('config.json','vpn_history.json')) {
    $src = Join-Path $OldDir $f
    if ((Test-Path $src) -and (Test-Path $Dist)) {
        Copy-Item $src (Join-Path $Dist $f) -Force -ErrorAction SilentlyContinue
    }
}
```

> 更根本的長遠解法：把使用者資料改存到 `%APPDATA%`，徹底脫離安裝目錄。這裡為了不破壞既有使用者設定位置，先用「搬回」應急。

### 坑 8：重啟要等「正確的程序名」退出

- **現象**：與坑 2 連動——等錯程序名，導致交換時檔案還被鎖。
- **解法**：`Get-Process -Name` 用的名字必須來自 `_frozen_exe_path()` 的 basename（去掉 `.exe`），不能來自 `sys.executable`。

### 坑 9：測試時的低版本/高版本「雞生蛋」問題

- **現象**：想測「更新」卻永遠顯示「已是最新版本」。
- **根因**：自動更新是「執行中的程式（舊）去下載並套用新程式」。所以：
  1. 執行中的那個版本**必須低於**最新 release；
  2. 執行中的那個版本**必須已經包含更新程式碼**（才有能力去下載+套用）。
- **解法**：測試時用「含修正的低版本 commit」當起點，再發一版更高的 release 當目標。
  例如：`git checkout <含修正的 commit>`（version 還是舊的）→ build → 跑起來 → 它會抓到最新的更高版本去更新。

### 坑 10：`git checkout <commit>` 測試會讓工作區變 detached HEAD

- **現象**：測試途中提交的 commit 落在「分離 HEAD」，push 時 `Everything up-to-date`，修正根本沒上 main。
- **解法**：
  1. 養成習慣：`git checkout main` 再 `git cherry-pick <修正 commit>`，把修正搬回 main。
  2. 提交前先 `git branch --show-current` 確認不在 detached HEAD。
  3. 提交後 `git log --oneline main -N` 驗證歷史完整。

### 坑 11：Python 啟動背景替換腳本要用 `CREATE_NO_WINDOW`，不能用 `DETACHED_PROCESS`

- **現象**：主程式按「是」後正常關閉，但**沒有更新、也沒有重啟**；替換腳本的 log 完全沒寫出來（`update.log` 不存在、stderr 是 0 bytes），彷彿腳本從沒執行過。
- **根因**：`subprocess.Popen(..., creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)` 建立的 PowerShell 子程序啟動後就「消失」——被建立但沒真正跑到腳本內容，連第一行 log 都沒留下。這個 flag 組合對 `powershell.exe -File` 啟動背景腳本不可靠。
- **解法**：改用 `CREATE_NO_WINDOW`；路徑改走命令列參數（`-Dist -NewDir -OldDir -Exe -ExeName -Log`）；腳本以 `utf-8-sig`（BOM）寫入（見坑 4）；`$ErrorActionPreference = 'SilentlyContinue'`：

```python
creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
with open(err_path, "ab") as err_fd:
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", script_path,
         "-Dist", dist_dir, "-NewDir", new_dir, "-OldDir", old_dir,
         "-Exe", exe_path, "-ExeName", exe_name, "-Log", log_path],
        cwd=install_dir,
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=err_fd,
    )
```

> 偵錯技巧：先看替換腳本 log 有沒有 `apply start` 這第一行；若完全沒有，代表腳本根本沒被執行，優先懷疑 creationflag 用錯了。

### 坑 12：殘留的 `WinDivert64.sys` 被核心驅動鎖住，導致連續更新卡在舊版本

- **現象**：連續更新時，更新看似成功、程式也重啟了，版本號卻沒變（停在舊版）。替換腳本 log 每次都出現 `cleanup done=False`，安裝目錄殘留 `IntegratedApp.dist.old\WinDivert64.sys`，手動刪除得到「拒絕存取」。
- **根因**：
  1. WinDivert 核心驅動載入後**不會隨主程式結束而卸載**，其 `.sys` 映像檔持續被鎖定。
  2. 資料夾交換把 `IntegratedApp.dist` 改名為 `.old` 後，被鎖定的檔案路徑隨之變成 `.old\WinDivert64.sys`，清理階段刪不掉，`.old` 因而殘留（只剩這一個檔案）。
  3. 下一次更新時 `Remove-Item $OldDir` 仍失敗，`Rename-Item $Dist $OldDir` 因目標已存在而失敗；`$Dist` 仍是舊版、`.new` 換不上去。
  4. 舊的成功判斷 `if (Test-Path $Exe) { $ok = $true }` 只確認「有 exe」，而舊版 exe 一直都在 → 誤判成功 → 重新啟動的其實是舊版本。
- **解法**：
  1. 交換前先停止驅動：以 `Get-CimInstance Win32_SystemDriver` 找出 `WinDivert*` 後 `sc.exe stop`，釋放 `.sys` 鎖定。
  2. 殘留 `.old` 清不掉時改名為 `.old.stale.<時間戳>` 讓位，或改用帶時間戳的交換目標，不讓它阻擋 `Rename-Item`。
  3. 成功判斷改為「`.new` 已被消耗且 `.dist` 就位」，不可只看 exe 是否存在。
  4. 仍鎖住的殘留用 `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)` 排程下次開機刪除。

> 這是坑 6「同步重試」與坑 7「資料夾交換」的交叉盲點：重試再多次也刪不掉被核心鎖住的檔案，必須先卸載驅動。

> **一句話總結（這個坑最容易被誤判成「更新成功」）**：只要 `IntegratedApp.dist.old`
> 因為任何檔案被鎖住而刪不掉，下一次更新的 `Rename-Item $Dist $OldDir` 就會失敗，
> 而舊版的成功判斷只確認「有 exe」——舊 exe 一直都在——於是回報更新成功、
> 程式也重啟了，跑的卻仍是舊版。**看到「更新成功但版本號沒變」，先查替換腳本
> log 的 `cleanup done=False`，以及安裝目錄是否殘留 `.old`。**

### 坑 13：下載「走走停停、速度一直歸零」——是 CDN 突發傳輸 + 瞬時速度取樣，不是重試

- **現象**：更新進度條走走停停，過程中速度數十次歸零，要很久才完成；但用
  **瀏覽器**下載同一個檔案卻很順。
- **先確認是不是同一個伺服器**：是。API 的 `browser_download_url` 就是 release
  網頁上資產連結的那條 URL，兩者都 302 到 `release-assets.githubusercontent.com`
  的簽名 URL（可用 `curl -sIL` 追轉址鏈驗證）。所以問題不在「連到不同或錯誤的站」。
- **釐清不是重試造成的**：把 `_fetch_block` 包起來計數，實測 9 段下載
  **0 次重試**——歸零與重試邏輯無關。
- **真正的根因**：
  1. GitHub 的 CDN 以**突發**方式送資料（一次灌一批、然後停頓）。
  2. 速度若用 **0.5 秒瞬時值**估算，幾乎每個停頓窗都會剛好顯示 `0 B/s`。
     實測一個 32.7 MB 的下載出現 **183/243（75%）** 個 0 速度樣本。
  3. 次要因素：只走**單一路徑**、且分段數偏少（34 MB 只切 9 段）；
     若流量又被自己的轉址規則導到單一代理，並行串流會互相排擠。
- **解法**：
  1. 速度改用**數秒滑動視窗平均**（`SPEED_WINDOW = 3.0`），並夾在 0 以上。
  2. **提高並行度**：分段 4 MB → 1 MB、上限 16 → 32 段。
  3. **智能分流**（見 4.4）：實測後挑最快的路徑，而不是被動走單一路徑。
- **效果**：同一條不穩定的線路上，32.7 MB 由 **123 秒縮短到約 32 秒**，
  速度歸零樣本由 **75% 降到 13%**（剩下的都在尾端只剩 1～2 條連線、真的沒資料時）。

> 教訓：**「速度顯示」與「實際吞吐」是兩件事**。使用者回報的「歸零」很可能
> 只是取樣視窗太短造成的假象；先用 instrument 量「重試次數」，才能把
> 「顯示問題」與「網路問題」分開，不然會改錯地方。

---

## 六、安全注意事項

1. **SHA-256 校驗是底線**：下載的二進位檔必須通過校驗才解壓/套用，否則等於把供應鏈攻擊接進一個有系統層權限的工具。
2. **zip-slip 防護**：解壓前逐一檢查條目路徑是否仍在目標目錄內。
3. **不要打包 `config.json`**：使用者本機設定（含加密密碼）不能進 release 包，否則外流。
4. **程式碼簽章**：未簽章的 Nuitka/PyInstaller exe + 驅動安裝，很容易被 SmartScreen / 防毒誤報。正式對外釋出建議加 Authenticode 簽章（這是唯一無法自動化、需要你自有憑證的部分）。

---

## 七、一頁速查：發佈一版的標準動作

1. `version.py` 遞增 `APP_VERSION` → commit。
2. `git tag vX.Y.Z && git push --tags`（同時 push main）。
3. 等 CI 建完 GitHub Release（會自動產出 zip + SHA256SUMS.txt）。
4. 用「含更新程式碼的低版本」build 一個測試起點，跑「檢查更新」驗證下載→校驗→重啟→設定保留。

---

## 附錄：關鍵檔案對照

| 檔案 | 角色 |
|------|------|
| `version.py` | 版本號單一來源 |
| `updater.py` | 檢查/下載/校驗/解壓/替換腳本產生（純邏輯，無 GUI） |
| `_frozen_exe_path()` | 取得真正的 exe 路徑（繞過 Nuitka 的 `sys.executable` 陷阱） |
| `is_frozen()` | 三種打包器的凍結偵測 |
| `.github/workflows/release.yml` | tag 觸發自動打包 + 發 Release |
| 背景 `apply_update.ps1` | 等退出 → 交換 → 保留設定 → 重啟 → 清理 |
