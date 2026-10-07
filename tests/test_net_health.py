# -*- coding: utf-8 -*-
"""net_health 單元測試 — 目標選擇、判讀與探針注入。

判斷邏輯全部用注入的假 ping 驗證，不依賴真實網路；
只有最後幾個 smoke test 會真的碰本機網路。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import net_health  # noqa: E402 - 必須先插入 repo 根目錄到 sys.path
import network_utils  # noqa: E402


# ------------------------------------------------------------ 假探針

def _ping_factory(responding):
    """回傳 (ping, calls)；responding 是「會回覆」的目標集合。"""
    calls = []

    def ping(source_ip, target=None, timeout_ms=500):
        calls.append(target)
        if target in responding:
            return 7
        return net_health.UNREACHABLE_MS

    return ping, calls


# ------------------------------------------------------------ NetHealth

def test_net_health_labels():
    assert net_health.NetHealth(True, "icmp", "ok", None).label == "OK"
    assert net_health.NetHealth(False, "icmp", "down", None).label == "DOWN"
    assert net_health.NetHealth(None, "icmp", "?", None).label == "UNKNOWN"


def test_net_health_str_includes_source_and_reason():
    text = str(net_health.NetHealth(False, "icmp", "對外無回應", None))
    assert "DOWN" in text and "icmp" in text and "對外無回應" in text


# ------------------------------------------------------------ 目標選擇

def test_default_targets_starts_with_user_target():
    targets = net_health.default_targets("9.9.9.9")
    assert targets[0] == "9.9.9.9"


def test_default_targets_includes_builtin_target():
    assert network_utils.PING_TARGET in net_health.default_targets(None)


def test_default_targets_dedupes_when_primary_is_the_builtin():
    targets = net_health.default_targets(network_utils.PING_TARGET)
    assert targets.count(network_utils.PING_TARGET) == 1


def test_default_targets_span_multiple_operators():
    """單一業者擋 ICMP 不該讓我們誤判整條線路。"""
    targets = net_health.default_targets(None)
    assert len(targets) >= 3
    assert len(set(targets)) == len(targets)


def test_default_targets_skips_empty_primary():
    assert "" not in net_health.default_targets("")


# ------------------------------------------------------------ 判讀

def test_up_when_any_target_responds():
    ping, _ = _ping_factory({"1.1.1.1"})
    health = net_health.check_primary_network(
        targets=("8.8.8.8", "1.1.1.1"), ping=ping)
    assert health.alive is True
    assert "1.1.1.1" in health.reason
    assert health.detail["rtt_ms"] == 7


def test_up_short_circuits_after_first_reply():
    ping, calls = _ping_factory({"8.8.8.8"})
    net_health.check_primary_network(
        targets=("8.8.8.8", "1.1.1.1"), ping=ping)
    assert calls == ["8.8.8.8"]          # 有回應就不必再打其他目標


def test_down_when_all_targets_unreachable():
    """這正是 PPPoE 被停用的情境：每一台都連不上。"""
    ping, calls = _ping_factory(set())
    health = net_health.check_primary_network(
        targets=("8.8.8.8", "1.1.1.1"), ping=ping)
    assert health.alive is False
    assert "無回應" in health.reason
    assert calls == ["8.8.8.8", "1.1.1.1"]   # 全不通就必須打完所有目標


def test_unknown_sentinel_counts_as_unreachable():
    ping, _ = _ping_factory(set())
    health = net_health.check_primary_network(targets=("8.8.8.8",), ping=ping)
    assert health.alive is False


def test_none_result_counts_as_unreachable():
    """ping_address 若回 None（實作改動）也要算成不通，不能當成 0ms。"""
    health = net_health.check_primary_network(
        targets=("8.8.8.8",), ping=lambda *a, **k: None)
    assert health.alive is False


def test_probe_exception_counts_as_unreachable():
    def boom(*a, **k):
        raise OSError("no route")

    health = net_health.check_primary_network(targets=("8.8.8.8",), ping=boom)
    assert health.alive is False


def test_real_rtt_below_sentinel_is_reachable():
    just_under = net_health.UNREACHABLE_MS - 1
    health = net_health.check_primary_network(
        targets=("8.8.8.8",), ping=lambda *a, **k: just_under)
    assert health.alive is True


def test_timeout_is_forwarded_to_probe():
    seen = []

    def ping(source_ip, target=None, timeout_ms=500):
        seen.append(timeout_ms)
        return net_health.UNREACHABLE_MS

    net_health.check_primary_network(
        targets=("8.8.8.8",), timeout_ms=250, ping=ping)
    assert seen == [250]


def test_primary_is_used_when_no_explicit_targets():
    ping, calls = _ping_factory({"9.9.9.9"})
    health = net_health.check_primary_network(primary="9.9.9.9", ping=ping)
    assert health.alive is True
    assert calls[0] == "9.9.9.9"


# ------------------------------------------------------------ 真實探針

def test_real_probe_returns_nethealth():
    """端到端 smoke test：不管結果如何，型別與內容必須合理。"""
    health = net_health.check_primary_network()
    assert isinstance(health, net_health.NetHealth)
    assert health.alive in (True, False, None)
    assert health.reason


def test_reuses_network_utils_probe():
    """探針必須複用既有實作，不可以自己再寫一套 ICMP。"""
    seen = []

    def spy(source_ip, target=None, timeout_ms=500):
        seen.append(source_ip)
        return 5

    net_health.check_primary_network(targets=("8.8.8.8",), ping=spy)
    assert seen == [""]      # 與 NetworkMonitorWorker 相同的呼叫慣例


# ------------------------------------------------------------ 分類：派發結果

DOWN = net_health.NetHealth(False, "icmp", "對外全部無回應", None)
UP = net_health.NetHealth(True, "icmp", "對外可達", None)
UNKNOWN = net_health.NetHealth(None, "icmp", "無法判定", None)


def _fails(n):
    return [("10.0.0.%d" % i, False, None) for i in range(n)]


def test_classify_round_empty_is_not_outage():
    assert net_health.classify_round([], DOWN) == (False, "")


def test_classify_round_any_success_wins():
    """主網路真的斷了不可能連得上 ⇒ 有成功就不是環境問題。"""
    outcomes = [("1.1.1.1", False, None), ("2.2.2.2", True, True)]
    assert net_health.classify_round(outcomes, DOWN) == (False, "")


def test_classify_round_probe_down_confirms_outage():
    is_outage, reason = net_health.classify_round(_fails(1), DOWN)
    assert is_outage is True
    assert reason == DOWN.reason


def test_classify_round_structural_signal_without_probe():
    """一整輪全數失敗就是環境事件 —— 完全不碰網路，最可靠。"""
    is_outage, reason = net_health.classify_round(_fails(3), UP)
    assert is_outage is True
    assert "3" in reason


def test_classify_round_unknown_probe_still_uses_structure():
    is_outage, _ = net_health.classify_round(_fails(2), UNKNOWN)
    assert is_outage is True


def test_classify_round_single_failure_is_node_problem():
    assert net_health.classify_round(_fails(1), UP) == (False, "")
    assert net_health.classify_round(_fails(1), UNKNOWN) == (False, "")


def test_classify_round_respects_min_attempts():
    assert net_health.classify_round(_fails(2), UP, min_attempts=3) == \
        (False, "")
    assert net_health.classify_round(_fails(3), UP, min_attempts=3)[0] is True


def test_classify_round_ignores_unreliable_probe():
    """探針被實際連線結果推翻後，不能再單憑它判定環境中斷。"""
    is_outage, _ = net_health.classify_round(
        _fails(1), DOWN, probe_reliable=False)
    assert is_outage is False


def test_classify_round_unreliable_probe_still_allows_structure():
    is_outage, _ = net_health.classify_round(
        _fails(2), DOWN, probe_reliable=False)
    assert is_outage is True


# ------------------------------------------------------------ 分類：監視器

def test_classify_monitor_tick_all_offline():
    assert net_health.classify_monitor_tick(3, 3) is True


def test_classify_monitor_tick_partial_offline():
    assert net_health.classify_monitor_tick(2, 3) is False
    assert net_health.classify_monitor_tick(1, 2) is False


def test_classify_monitor_tick_single_nic_is_not_enough():
    """只有一張網卡時無從對照，不該斷定是環境問題。"""
    assert net_health.classify_monitor_tick(1, 1) is False


def test_classify_monitor_tick_nothing_monitored():
    assert net_health.classify_monitor_tick(0, 0) is False
