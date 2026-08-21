# -*- coding: utf-8 -*-
"""proxy_core.RouteManager 單元測試 — 選路與綁定邏輯 (無需 Qt/DLL)"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy_core import RouteManager


def make_rm(ifaces, bindings, max_conns=100000):
    rm = RouteManager()
    rm.interfaces = ifaces
    rm.port_bindings = bindings
    rm.max_conns_per_ip = max_conns
    return rm


def test_no_binding_returns_none():
    rm = make_rm({"A": {"connected": True, "ip": "10.0.0.1", "active_conns": 0, "latency": 1}}, {})
    assert rm.allocate_best_ip(1080) == (None, None)


def test_no_candidates_returns_none():
    rm = make_rm(
        {"A": {"connected": False, "ip": None, "active_conns": 0, "latency": 9999}},
        {1080: ["A"]},
    )
    assert rm.allocate_best_ip(1080) == (None, None)


def test_picks_lowest_latency():
    rm = make_rm(
        {
            "Fast": {"connected": True, "ip": "10.0.0.1", "active_conns": 0, "latency": 5},
            "Slow": {"connected": True, "ip": "10.0.0.2", "active_conns": 0, "latency": 100},
        },
        {1080: ["Fast", "Slow"]},
    )
    ip, name = rm.allocate_best_ip(1080)
    assert name == "Fast"
    assert ip == "10.0.0.1"


def test_prefers_lower_active_conns():
    rm = make_rm(
        {
            "Busy": {"connected": True, "ip": "10.0.0.1", "active_conns": 5, "latency": 1},
            "Idle": {"connected": True, "ip": "10.0.0.2", "active_conns": 0, "latency": 9999},
        },
        {1080: ["Busy", "Idle"]},
    )
    # 活躍數低的優先 (即使延遲高)。Idle 累加到 5 之前 (5 次) 都會被選中
    for _ in range(5):
        ip, name = rm.allocate_best_ip(1080)
        assert name == "Idle"
    # Idle 累加到 5 後與 Busy 平手，延遲較低的 Busy 勝出 (活躍數為主鍵的設計)
    ip, name = rm.allocate_best_ip(1080)
    assert name == "Busy"


def test_exclude_names_honored():
    rm = make_rm(
        {"A": {"connected": True, "ip": "10.0.0.1", "active_conns": 0, "latency": 1}},
        {1080: ["A", "B"]},
    )
    assert rm.allocate_best_ip(1080, exclude_names={"A"}) == (None, None)


def test_max_conns_cap():
    rm = make_rm(
        {"A": {"connected": True, "ip": "10.0.0.1", "active_conns": 49, "latency": 1}},
        {1080: ["A"]},
        max_conns=50,
    )
    assert rm.allocate_best_ip(1080)[0] == "10.0.0.1"
    # 達到上限後回傳 None
    rm.interfaces["A"]["active_conns"] = 50
    assert rm.allocate_best_ip(1080) == (None, None)


def test_active_conns_increments_and_decrements():
    rm = make_rm(
        {"A": {"connected": True, "ip": "10.0.0.1", "active_conns": 0, "latency": 1}},
        {1080: ["A"]},
    )
    rm.allocate_best_ip(1080)
    assert rm.interfaces["A"]["active_conns"] == 1
    rm.decrement_conn("A")
    assert rm.interfaces["A"]["active_conns"] == 0


def test_update_port_binding():
    rm = make_rm({}, {})
    rm.update_port_binding(1080, ["A", "B"])
    assert rm.port_bindings[1080] == ["A", "B"]
