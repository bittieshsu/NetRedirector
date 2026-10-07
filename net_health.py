# -*- coding: utf-8 -*-
"""net_health.py — 判斷「主網路還活著嗎」（通用，不綁特定路由器廠牌）。

用途：VPN Gate 的穩定度評分衡量的是「節點自己的表現」。但主網路一斷，
所有節點都會連線失敗，於是全部被記成爛節點 —— 連續失敗 5 次失敗懲罰就
吃滿 1.00，而加分項上限只有 0.90，穩定度在數學上直接歸零；而且
connect_rate 是終身比率，傷害是永久的。本模組提供「這是不是我自己的網路
壞了」的判準，讓呼叫端把環境因素從節點評價裡剔除。

探針直接複用既有的 `network_utils.ping_address()` —— 也就是介面上
「核心延遲」那顆徽章用的同一支，不另外實作一套 ICMP。

為什麼非得是 ICMP
-----------------
本程式引擎是 WinDivert 攔截器，過濾條件只有 tcp 與 udp 兩種子句
（`NetRedirector/NetRedirector.c` 的 `build_windivert_filter()`），
**沒有任何 icmp 子句** ⇒ ICMP echo 根本不會進到引擎，也就不可能被轉走。

這點是關鍵：引擎有 catch-all `* -> PROXY` 規則。主網路斷線時，代理
（手機熱點）仍在同一段 LAN 上活著，任何 TCP/UDP 探針都會被引擎轉去代理而
照樣成功 ⇒ 探針回報「網路正常」，正好在最需要它的時候騙人。
`ping_address()` 走 `IcmpSendEcho`，因此沒有這個問題。

為什麼不直接讀「核心延遲」徽章的讀數
------------------------------------
`NetworkMonitorWorker` 只在 index 0 的分頁啟用 ping
（`IntegratedApp.on_tab_changed`: `set_ping_enabled(index == 0)`），
而 VPNGate 是 index 4 ⇒ 使用者停在 VPNGate 分頁時那個讀數是舊的。
所以本模組自己呼叫 `ping_address()`：複用實作，不複用它的排程。
"""

import collections

import network_utils

# ping_address() 的失敗哨兵值：回傳值大於等於它就代表不可達。
UNREACHABLE_MS = 9999
DEFAULT_TIMEOUT_MS = 1000

# 不同營運商的備援目標：單一業者擋 ICMP 不至於讓我們誤判整條線路。
FALLBACK_TARGETS = ("1.1.1.1", "223.5.5.5")


# ------------------------------------------------------------ 結果型別

class NetHealth(collections.namedtuple(
        "NetHealth", "alive source reason detail")):
    """主網路健康狀態。

    alive: True = 主網路可用 / False = 主網路斷了 / None = 無法判定。

    呼叫端務必把 None 當成「不知道」而不是「壞消息」。
    """
    __slots__ = ()

    @property
    def label(self):
        return {True: "OK", False: "DOWN"}.get(self.alive, "UNKNOWN")

    def __str__(self):
        return "%s (%s: %s)" % (self.label, self.source, self.reason)


def _unknown(reason, detail=None):
    return NetHealth(None, "icmp", reason, detail)


# ------------------------------------------------------------ 目標

def default_targets(primary=None):
    """要探的目標：使用者設定的優先，再補上不同營運商的備援。"""
    out = []
    for host in (primary, network_utils.PING_TARGET) + FALLBACK_TARGETS:
        if host and host not in out:
            out.append(host)
    return tuple(out)


# ------------------------------------------------------------ 主入口

def check_primary_network(targets=None, timeout_ms=DEFAULT_TIMEOUT_MS,
                          ping=None, primary=None):
    """回傳 NetHealth。

    ping 預設為 network_utils.ping_address（既有實作），可注入以便測試。
    本函式會阻塞最多 len(targets) × timeout_ms，請在背景執行緒呼叫。
    """
    ping = ping or network_utils.ping_address
    targets = tuple(targets) if targets else default_targets(primary)

    tried = []
    for host in targets:
        try:
            rtt = ping("", target=host, timeout_ms=timeout_ms)
        except Exception:
            rtt = None
        tried.append(host)
        if rtt is not None and rtt < UNREACHABLE_MS:
            return NetHealth(
                True, "icmp", "對外可達（%s %dms）" % (host, rtt),
                {"target": host, "rtt_ms": rtt},
            )
    return NetHealth(
        False, "icmp", "對外全部無回應（%s）" % "、".join(tried),
        {"targets": list(tried)},
    )


# ------------------------------------------------------------ 分類

def classify_round(outcomes, health=None, probe_reliable=True,
                   min_attempts=2):
    """判斷一輪派發的失敗是「環境問題」還是「節點問題」，回傳 (bool, 原因)。

    outcomes 是 [(node_ip, session_ok, tunnel_ok), ...]。

    有任何一次 session 成功就一律不算環境問題 —— 主網路真的斷了不可能連得上。
    否則依序看兩條判準：
      1. 探針（且未被實際連線結果推翻）明確判定主網路中斷。
      2. 結構啟發式：嘗試了足夠多個節點卻全數失敗。主網路斷線時每一台都會
         失敗，這個訊號完全不碰網路，最可靠。
    """
    outcomes = list(outcomes or [])
    if not outcomes or any(ok for _, ok, _ in outcomes):
        return False, ""
    if probe_reliable and health is not None and health.alive is False:
        return True, health.reason
    if len(outcomes) >= min_attempts:
        return True, "連續 %d 個節點全數失敗" % len(outcomes)
    return False, ""


def classify_monitor_tick(offline_count, monitored_count):
    """監視器一輪的結果是否代表「環境事件」。

    所有受監控的網卡在同一輪同時離線 ⇒ 幾乎一定是自己的網路斷了，而不是
    這些節點剛好同時被踢。只算「離線」的網卡，不含「假連線」（那是節點問題）。
    單張網卡離線不足以斷定，因此要求至少 2 張。
    """
    return monitored_count >= 2 and offline_count == monitored_count
