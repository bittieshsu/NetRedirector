# -*- coding: utf-8 -*-
"""Windows 網路介面計量 (metric) 管理。

SoftEther 虛擬網卡建立時 IPv4 計量是「自動」，而 SoftEther VPN Client
預設會把 VPN 設成預設閘道。多張虛擬網卡連線後，路由表會出現多條
0.0.0.0/0；自動計量彼此接近、甚至低於實體網卡時，Windows 可能改走某張
VPN 網卡當預設路由，導致程式自身的節點抓取/更新檢查、DNS 查詢與使用者
的一般瀏覽被劫走或來回抖動。

本模組在程式啟動與「重新整理網卡」時，把 SoftEther 虛擬網卡的 IPv4 計量
固定為 config.VPN_INTERFACE_METRIC (10)，並把目前承接預設路由的實體網卡
固定為 config.PHYSICAL_INTERFACE_METRIC (1)，確保實體網卡是主網路。被
規則重導的流量本來就以來源 IP 綁定出口網卡，不受計量影響。

Set-NetIPInterface 需要管理員權限；本程式載入 WinDivert 驅動時已要求
最高權限，故可直接執行。設定會持久化 (寫入介面設定，重開機仍有效)。
"""

import subprocess
import sys

import vpngate_config as config

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# 佔位符以 replace 填入，避免 .format 與 PowerShell 的大括號互相衝突。
_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$vpn = @(Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like '*SoftEther*' -or $_.Name -like 'VPN*'
})
if ($vpn.Count -eq 0) {
    Write-Output 'NOVPN'
    exit 0
}

$vpnNames = @($vpn | ForEach-Object { $_.Name })
foreach ($n in $vpnNames) {
    Set-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4 -InterfaceMetric __VPN_METRIC__
    Write-Output ('VPN|' + $n)
}

# 實體網卡：優先挑目前承接預設路由者，沒有才退回第一張 Up 的實體網卡。
$phys = Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
    Where-Object { $vpnNames -notcontains $_.InterfaceAlias } |
    Sort-Object RouteMetric | Select-Object -First 1
$physName = $null
if ($phys) { $physName = $phys.InterfaceAlias }
if (-not $physName) {
    $ad = Get-NetAdapter |
        Where-Object { -not $_.Virtual -and $_.Status -eq 'Up' } |
        Select-Object -First 1
    if ($ad) { $physName = $ad.Name }
}
if ($physName) {
    Set-NetIPInterface -InterfaceAlias $physName -AddressFamily IPv4 -InterfaceMetric __PHYS_METRIC__
    Write-Output ('PHYS|' + $physName)
}
"""


def _build_script(vpn_metric, physical_metric):
    return (
        _PS_SCRIPT
        .replace("__VPN_METRIC__", str(int(vpn_metric)))
        .replace("__PHYS_METRIC__", str(int(physical_metric)))
    )


def ensure_metrics(vpn_metric=None, physical_metric=None):
    """校正 SoftEther 虛擬網卡與實體網卡的 IPv4 計量。

    回傳 dict:
        ok        是否成功執行 (非 Windows 或命令失敗為 False)
        vpn       已設定計量的虛擬網卡名稱清單
        physical  已設定計量的實體網卡名稱 (無則 None)
        no_vpn    系統上找不到 SoftEther 虛擬網卡 (此時不動實體網卡)
        error     失敗原因 (成功為 None)
        vpn_metric / physical_metric  實際套用的數值
    """
    vpn_metric = config.VPN_INTERFACE_METRIC if vpn_metric is None else vpn_metric
    physical_metric = (
        config.PHYSICAL_INTERFACE_METRIC if physical_metric is None else physical_metric
    )
    result = {
        "ok": False,
        "vpn": [],
        "physical": None,
        "no_vpn": False,
        "error": None,
        "vpn_metric": vpn_metric,
        "physical_metric": physical_metric,
    }
    if not sys.platform.startswith("win"):
        result["error"] = "unsupported platform"
        return result

    try:
        proc = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", _build_script(vpn_metric, physical_metric),
            ],
            capture_output=True,
            timeout=30,
            creationflags=_CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as e:
        result["error"] = str(e)
        return result

    if proc.returncode != 0:
        stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        result["error"] = stderr or f"powershell rc={proc.returncode}"
        return result

    out = (proc.stdout or b"").decode("utf-8", errors="replace")
    for line in out.splitlines():
        line = line.strip()
        if line == "NOVPN":
            result["no_vpn"] = True
        elif line.startswith("VPN|"):
            name = line[len("VPN|"):].strip()
            if name:
                result["vpn"].append(name)
        elif line.startswith("PHYS|"):
            result["physical"] = line[len("PHYS|"):].strip() or None

    result["ok"] = True
    return result
