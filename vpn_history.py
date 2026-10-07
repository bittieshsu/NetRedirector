# -*- coding: utf-8 -*-
"""VPN Gate 節點持久化池 + 穩定度評分 (純邏輯、無 GUI)。

以 ip 去重累積「所有見過的節點」，跨次啟動保留。每次連線/斷線/被踢
都累加統計，最終以長期成功率 + tunnel 成功率 + 平均 session 時長
計算穩定度 (0~1)，取代官方 Score 作為派發排序依據。

檔案 I/O 直接復用 config_store 的原子寫入與氈損檔案保留邏輯。
"""

import time

import config_store
import vpngate_config as config


# ---------------------------------------------------------------- 檔案 I/O

def load_history(path=config.VPN_HISTORY_FILE):
    """讀取節點池。檔案不存在/氈損/讀取失敗一律回傳空池 (不崩潰)。"""
    data = config_store.load_config_file(path)
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), dict):
        return {"version": 1, "nodes": {}}
    data.setdefault("version", 1)
    return data


def save_history(path, history):
    """原子寫入節點池，失敗回傳錯誤字串 (成功回傳 None)。"""
    return config_store.save_config_file(path, history)


# ---------------------------------------------------------------- 節點記錄

# 由「本程式實際觀測」累積出來的欄位。reset_stability() 只歸零這些；
# 節點快照欄位 (port/hostname/國家/last_score/last_ping/last_speed) 與
# first_seen/last_seen 一律保留 —— 特別是 last_seen 是 prune() 判斷過期的
# 唯一依據，清掉會讓整個節點池在下一輪被當成陳舊資料淘汰掉。
_STAT_FIELDS = (
    "connect_attempts",
    "connect_successes",
    "tunnel_checks",
    "tunnel_ok",
    "session_count",
    "total_connected_seconds",
    "disconnect_count",
    "consecutive_failures",
)


def _empty_record(ip):
    now = int(time.time())
    rec = {
        "ip": ip,
        "port": 0,
        "hostname": "",
        "country_long": "",
        "country_short": "",
        "first_seen": now,
        "last_seen": now,
        "last_score": 0,
        "last_ping": 0,
        "last_speed": 0,
    }
    rec.update(dict.fromkeys(_STAT_FIELDS, 0))
    return rec


def upsert_node(history, node):
    """以 node.ip 為鍵合併單次 fetch 的快照欄位，保留累積統計。

    node 為 vpngate.VpnGateNode (duck-typed, 不 import 以避免耦合)。
    """
    nodes = history.setdefault("nodes", {})
    rec = nodes.get(node.ip)
    if rec is None:
        rec = _empty_record(node.ip)
        nodes[node.ip] = rec
    rec["last_seen"] = int(time.time())
    rec["port"] = node.port
    rec["hostname"] = node.hostname
    rec["country_long"] = node.country_long
    rec["country_short"] = node.country_short
    rec["last_score"] = node.score
    rec["last_ping"] = node.ping_ms
    rec["last_speed"] = node.speed_bps
    return rec


def _get(history, ip):
    nodes = history.get("nodes")
    if not isinstance(nodes, dict):
        return None
    return nodes.get(ip)


def record_connect(history, ip, ok, tunnel_ok=None):
    """記錄一次連線結果。

    - ok: session 是否建立 (account_connect 成功)。
    - tunnel_ok: 資料路徑是否可達 (True/False)，未測過給 None。
    連線成功將 consecutive_failures 歸零；失敗則遞增。
    """
    rec = _get(history, ip)
    if rec is None:
        return None
    rec["connect_attempts"] += 1
    if ok:
        rec["connect_successes"] += 1
        rec["consecutive_failures"] = 0
    else:
        rec["consecutive_failures"] += 1
    if tunnel_ok is not None:
        rec["tunnel_checks"] += 1
        if tunnel_ok:
            rec["tunnel_ok"] += 1
    return rec


def record_session(history, ip, duration_sec):
    """記錄一次已結束的 session 時長 (秒)。"""
    rec = _get(history, ip)
    if rec is None:
        return None
    rec["session_count"] += 1
    rec["total_connected_seconds"] += max(0, int(duration_sec))
    return rec


def record_disconnect(history, ip):
    """記錄一次非預期中斷 (被踢 / 假連線已死)。"""
    rec = _get(history, ip)
    if rec is None:
        return None
    rec["disconnect_count"] += 1
    return rec


def reset_stability(history, ips=None):
    """歸零累積統計，讓節點回到「冷啟動中性 0.5」。

    用途：主網路中斷 (例如 PPPoE 被停用) 期間，所有節點都會連線失敗，
    這些失敗不是節點的問題，卻會把 connect_rate 這個「終身比率」永久打爛
    (consecutive_failures 只要 5 次，失敗懲罰就吃滿 1.00，而加分項上限只有
    0.90 ⇒ 穩定度數學上直接歸零)。此時需要一個把污染清掉的出口。

    只清 _STAT_FIELDS；節點池本身、快照欄位與 first_seen/last_seen 保留。
    ips=None 表示重置池中全部節點。回傳實際被重置的節點數。
    """
    nodes = history.get("nodes")
    if not isinstance(nodes, dict):
        return 0
    if ips is None:
        targets = list(nodes.values())
    else:
        targets = [nodes[ip] for ip in ips if ip in nodes]
    count = 0
    for rec in targets:
        if not isinstance(rec, dict):
            continue
        for field in _STAT_FIELDS:
            rec[field] = 0
        count += 1
    return count


def forgive_failures(history, ips=None):
    """只把 consecutive_failures 歸零 (其餘統計保留)。

    主網路恢復後呼叫：中斷期間的連續失敗是環境造成的，不該繼續壓著節點；
    但 connect_attempts / successes 這些歷史比率仍保留，避免把真實的
    節點品質也一併洗掉。回傳實際被更動的節點數。
    """
    nodes = history.get("nodes")
    if not isinstance(nodes, dict):
        return 0
    if ips is None:
        targets = list(nodes.values())
    else:
        targets = [nodes[ip] for ip in ips if ip in nodes]
    count = 0
    for rec in targets:
        if not isinstance(rec, dict):
            continue
        if rec.get("consecutive_failures", 0):
            rec["consecutive_failures"] = 0
            count += 1
    return count


# ---------------------------------------------------------------- 穩定度

def stability(rec):
    """回傳 0~1 穩定度。無任何連線嘗試的冷啟動節點給中性 0.5。

    維度: 連線成功率、tunnel 成功率、平均 session 時長 (加分)，
          被踢次數、連續失敗 (減分)。
    """
    if not isinstance(rec, dict):
        return 0.5
    attempts = rec.get("connect_attempts", 0)
    if attempts <= 0:
        return 0.5

    w_connect, w_tunnel, w_duration, w_kick, w_fail = config.STABILITY_WEIGHTS

    connect_rate = rec.get("connect_successes", 0) / attempts

    tunnel_checks = rec.get("tunnel_checks", 0)
    tunnel_rate = rec.get("tunnel_ok", 0) / max(1, tunnel_checks)

    session_count = rec.get("session_count", 0)
    if session_count > 0:
        avg_sec = rec.get("total_connected_seconds", 0) / session_count
    else:
        avg_sec = 0.0
    duration_score = min(avg_sec / config.STABILITY_DURATION_FULL_SEC, 1.0)

    kick_penalty = min(rec.get("disconnect_count", 0) / config.STABILITY_KICK_FULL, 1.0)
    fail_penalty = min(rec.get("consecutive_failures", 0), config.STABILITY_FAIL_CAP)

    s = (
        w_connect * connect_rate
        + w_tunnel * tunnel_rate
        + w_duration * duration_score
        - w_kick * kick_penalty
        - w_fail * fail_penalty
    )
    return max(0.0, min(1.0, s))


# ---------------------------------------------------------------- 汰除

def prune(history, max_nodes=None, max_age_days=None):
    """汰除太久未見的節點；超量時依穩定度優先剔除低分者。"""
    if max_nodes is None:
        max_nodes = config.HISTORY_PRUNE_MAX_NODES
    if max_age_days is None:
        max_age_days = config.HISTORY_PRUNE_MAX_AGE_DAYS
    nodes = history.get("nodes")
    if not isinstance(nodes, dict):
        return history

    now = int(time.time())
    cutoff = now - max_age_days * 86400
    kept = {
        ip: rec
        for ip, rec in nodes.items()
        if rec.get("last_seen", 0) >= cutoff
    }

    if len(kept) > max_nodes:
        ranked = sorted(
            kept.items(),
            key=lambda kv: (stability(kv[1]), kv[1].get("last_seen", 0)),
        )
        keep = {ip for ip, _ in ranked[-max_nodes:]}
        kept = {ip: rec for ip, rec in kept.items() if ip in keep}

    history["nodes"] = kept
    return history
