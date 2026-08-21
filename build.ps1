<#
.SYNOPSIS
    NetRedirector 統一建置腳本。自動偵測 MSVC Build Tools 編譯 C DLL，
    並可選執行 Nuitka 打包為獨立執行檔。

.DESCRIPTION
    取代 nuitka_packager.py GUI 的 CLI 建置方案。支援三種模式：
    - 預設：僅編譯 DLL (最快)
    - -Standalone：編譯 DLL + Nuitka 目錄模式
    - -Onefile：編譯 DLL + Nuitka 單一 exe 模式

.PARAMETER DllOnly
    僅編譯 DLL (預設行為)，不執行 Nuitka 打包。

.PARAMETER Standalone
    編譯 DLL 後以 Nuitka --standalone 模式打包 (產出目錄)。

.PARAMETER Onefile
    編譯 DLL 後以 Nuitka --onefile 模式打包 (產出單一 exe)。

.PARAMETER EntryPoint
    打包入口腳本，預設為 IntegratedApp.py。

.PARAMETER ConsoleMode
    打包時保留主控台視窗 (預設隱藏主控台)。

.PARAMETER NoDll
    跳過 DLL 編譯 (僅執行 Nuitka 打包，需已有編譯好的 DLL)。

.EXAMPLE
    .\build.ps1                        # 僅編譯 DLL
    .\build.ps1 -Standalone            # 編譯 DLL + 打包 standalone
    .\build.ps1 -Onefile -ConsoleMode  # 編譯 DLL + 打包單一 exe (含主控台)
    .\build.ps1 -Standalone -NoDll     # 僅打包 (跳過 DLL 編譯)
#>

param(
    [switch]$DllOnly,
    [switch]$Standalone,
    [switch]$Onefile,
    [string]$EntryPoint = "IntegratedApp.py",
    [switch]$ConsoleMode,
    [switch]$NoDll
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ============================================================
# 步驟 1: 編譯 C DLL
# ============================================================
if (-not $NoDll) {
    Write-Host "=== 編譯 NetRedirector.dll ===" -ForegroundColor Cyan

    # 嘗試透過 vswhere 找到 MSVC 環境
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    }

    $vcvars = $null
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath
        if ($vsPath) {
            # 嘗試多個可能的 vcvars64.bat 路徑
            $candidates = @(
                "$vsPath\VC\Auxiliary\Build\vcvars64.bat",
                "$vsPath\VC\Auxiliary\Build\vcvarsamd64.bat",
                "$vsPath\Common7\Tools\VsDevCmd.bat"
            )
            foreach ($c in $candidates) {
                if (Test-Path $c) { $vcvars = $c; break }
            }
        }
    }

    # 備用: 常見 VS 2022 Build Tools 路徑
    if (-not $vcvars) {
        $fallback = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $fallback) { $vcvars = $fallback }
    }

    if (-not $vcvars) {
        Write-Warning "找不到 MSVC Build Tools。請先安裝 Visual Studio Build Tools 2022 或從 Developer Command Prompt 執行此腳本。"
        Write-Warning "嘗試直接用 cl... (需已在 PATH 上)"
    } else {
        Write-Host "  找到 vcvars64.bat: $vcvars"
    }

    $dllDir = "NetRedirector"
    $dllSrc = @(
        "NetRedirector.c", "NR_Core.c", "NR_Protocol.c",
        "NR_RuleEngine.c", "NR_State.c", "NR_Utils.c"
    )
    $dllLibs = "windivert.lib User32.lib Advapi32.lib Ws2_32.lib Iphlpapi.lib"

    # 透過暫存 .bat 執行 vcvars64 + cl，避免 cmd 引號巢狀問題
    $batPath = Join-Path $env:TEMP "build_dll_$PID.bat"
    $batContent = "@echo off`r`n"
    if ($vcvars) {
        $batContent += "`"$vcvars`" >nul 2>&1`r`n"
    }
    $batContent += "cl /nologo /LD /DNETREDIRECTOR_EXPORTS $($dllSrc -join ' ') /Fe:NetRedirector.dll /I. $dllLibs"
    [System.IO.File]::WriteAllText($batPath, $batContent)

    Write-Host "  執行 cl: $($dllSrc -join ' ')" -ForegroundColor Gray
    $process = Start-Process -FilePath $batPath -WorkingDirectory $dllDir -NoNewWindow -Wait -PassThru
    Remove-Item $batPath -Force -ErrorAction SilentlyContinue

    if ($process.ExitCode -ne 0) {
        Write-Error "DLL 編譯失敗 (exit code: $($process.ExitCode))"
        exit 1
    }

    # 複製 DLL 到專案根目錄 (若被執行中的應用程式鎖定，提示後不中斷)
    try {
        Copy-Item "$dllDir\NetRedirector.dll" "NetRedirector.dll" -Force -ErrorAction Stop
        Write-Host "  DLL 編譯成功！已複製到 NetRedirector.dll" -ForegroundColor Green
    } catch {
        Write-Warning "  DLL 已編譯，但無法覆寫根目錄 NetRedirector.dll (檔案被佔用，應用程式可能正在執行)。"
        Write-Warning "  請關閉 NetRedirector 應用程式後重新執行本腳本，或手動複製: Copy-Item NetRedirector\NetRedirector.dll NetRedirector.dll -Force"
    }
}

# ============================================================
# 步驟 2: Nuitka 打包 (僅在指定 -Standalone 或 -Onefile 時)
# ============================================================
if (-not ($Standalone -or $Onefile)) {
    Write-Host "=== 完成 (DLL only) ===" -ForegroundColor Cyan
    exit 0
}

Write-Host "=== Nuitka 打包 ===" -ForegroundColor Cyan

# 確認入口腳本存在
if (-not (Test-Path $EntryPoint)) {
    Write-Error "找不到入口腳本: $EntryPoint"
    exit 1
}

# 建構 Nuitka 命令
$mode = if ($Onefile) { "--onefile" } else { "--standalone" }
$nuitkaCmd = @(
    "python", "-m", "nuitka",
    "$mode",
    "--enable-plugin=pyside6",
    "--include-data-dir=locale=locale"
)

if (-not $ConsoleMode) {
    $nuitkaCmd += "--windows-console-mode=disable"
}

# 包含執行時期支援檔案 (DLL / 驅動 / 設定檔)
$runtimeFiles = @("NetRedirector.dll", "WinDivert.dll", "WinDivert64.sys", "config.json")
foreach ($f in $runtimeFiles) {
    if (Test-Path $f) {
        $nuitkaCmd += "--include-data-files=$f=$f"
    }
}

$nuitkaCmd += "--remove-output"
$nuitkaCmd += $EntryPoint

Write-Host "  執行: $($nuitkaCmd -join ' ')" -ForegroundColor Gray
Write-Host "" -ForegroundColor Gray

$global:lastExitCode = 0
& $nuitkaCmd
if ($LASTEXITCODE -ne 0) {
    Write-Error "Nuitka 打包失敗 (exit code: $LASTEXITCODE)"
    exit 1
}

Write-Host ""
Write-Host "=== 建置完成！ ===" -ForegroundColor Green
if ($Onefile) {
    Write-Host "  exe 產出: ${EntryPoint}.onefile-dist\$([System.IO.Path]::GetFileNameWithoutExtension($EntryPoint)).exe" -ForegroundColor Yellow
    Write-Host "  注意: 單一 exe 首次啟動時會自行解壓，可能導致防毒軟體誤報。" -ForegroundColor Yellow
} else {
    Write-Host "  目錄: ${EntryPoint}.dist\" -ForegroundColor Yellow
    Write-Host "  注意: 執行前確認 WinDivert64.sys 與 WinDivert.dll 在同目錄。" -ForegroundColor Yellow
}