# -*- coding: utf-8 -*-
"""interface_metrics 單元測試 — PowerShell 計量校正腳本與結果解析。

外部命令 (powershell) 一律以 mock 取代，不實際更動系統網路設定。
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import interface_metrics


def _proc(rc=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(["powershell"], rc, stdout, stderr)


def test_script_embeds_metrics():
    script = interface_metrics._build_script(10, 1)
    assert "-InterfaceMetric 10" in script
    assert "-InterfaceMetric 1" in script
    assert "__VPN_METRIC__" not in script
    assert "__PHYS_METRIC__" not in script


def test_script_targets_softether_and_physical():
    script = interface_metrics._build_script(7, 3)
    # 以描述或名稱辨識 SoftEther 虛擬網卡
    assert "SoftEther" in script
    assert "VPN*" in script
    # 實體網卡排除虛擬網卡名稱後，優先挑承接預設路由者
    assert "0.0.0.0/0" in script
    assert "$_.Virtual" in script


def test_ensure_metrics_parses_output(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _proc(0, b"VPN|VPN2\nVPN|VPN3\nPHYS|\xe4\xb9\x99\xe5\xa4\xaa\xe7\xb6\xb2\xe8\xb7\xaf\n")

    monkeypatch.setattr(interface_metrics.sys, "platform", "win32")
    monkeypatch.setattr(interface_metrics.subprocess, "run", fake_run)

    result = interface_metrics.ensure_metrics()
    assert result["ok"] is True
    assert result["vpn"] == ["VPN2", "VPN3"]
    assert result["physical"] == "乙太網路"
    assert result["no_vpn"] is False
    assert result["error"] is None
    # 命令必須是無視窗的 PowerShell 且帶 UTF-8 輸出設定
    assert captured["cmd"][0] == "powershell"
    assert "-NoProfile" in captured["cmd"]


def test_ensure_metrics_no_vpn(monkeypatch):
    monkeypatch.setattr(interface_metrics.sys, "platform", "win32")
    monkeypatch.setattr(
        interface_metrics.subprocess, "run", lambda *a, **k: _proc(0, b"NOVPN\n"))
    result = interface_metrics.ensure_metrics()
    assert result["ok"] is True
    assert result["no_vpn"] is True
    assert result["vpn"] == []
    assert result["physical"] is None


def test_ensure_metrics_command_failure(monkeypatch):
    monkeypatch.setattr(interface_metrics.sys, "platform", "win32")
    monkeypatch.setattr(
        interface_metrics.subprocess, "run",
        lambda *a, **k: _proc(1, b"", b"Access is denied"))
    result = interface_metrics.ensure_metrics()
    assert result["ok"] is False
    assert "Access is denied" in result["error"]


def test_ensure_metrics_handles_oserror(monkeypatch):
    def boom(*a, **k):
        raise OSError("powershell not found")

    monkeypatch.setattr(interface_metrics.sys, "platform", "win32")
    monkeypatch.setattr(interface_metrics.subprocess, "run", boom)
    result = interface_metrics.ensure_metrics()
    assert result["ok"] is False
    assert "powershell not found" in result["error"]


def test_non_windows_is_noop(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("非 Windows 不應呼叫外部命令")

    monkeypatch.setattr(interface_metrics.sys, "platform", "linux")
    monkeypatch.setattr(interface_metrics.subprocess, "run", fail)
    result = interface_metrics.ensure_metrics()
    assert result["ok"] is False
    assert result["error"] == "unsupported platform"


def test_custom_metrics_override_defaults(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _proc(0, b"NOVPN\n")

    monkeypatch.setattr(interface_metrics.sys, "platform", "win32")
    monkeypatch.setattr(interface_metrics.subprocess, "run", fake_run)
    result = interface_metrics.ensure_metrics(vpn_metric=25, physical_metric=2)
    assert result["vpn_metric"] == 25
    assert result["physical_metric"] == 2
    script = captured["cmd"][-1]
    assert "-InterfaceMetric 25" in script
    assert "-InterfaceMetric 2" in script
