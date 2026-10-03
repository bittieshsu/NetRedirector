// --- START OF FILE NR_RuleEngine.h ---
#ifndef NR_RULE_ENGINE_H
#define NR_RULE_ENGINE_H

#include "NR_Common.h"
#include "NR_Utils.h"
#include "NR_State.h"

// Core matching logic
RuleAction match_rule(DWORD current_pid, const char *process_name, int family, const UINT8 *dest_addr, UINT16 dest_port, BOOL is_udp, UINT32* out_proxy_id);

// Higher level check (includes PID resolution and exclusion)
//
// [Perf] pid_in / have_pid let the caller hand over a PID it has ALREADY
// resolved for this exact (family, src_addr, src_port, is_udp). When have_pid
// is TRUE the resolution chain is skipped entirely - including the pid==0 case,
// which matters because a failed resolution is deliberately not cached, so
// re-running it costs another whole-table GetExtendedTcpTable (~650 us).
// Pass have_pid = FALSE to keep the original resolve-it-yourself behaviour.
RuleAction check_process_rule(int family, const UINT8 *src_addr, UINT16 src_port, const UINT8 *dest_addr, UINT16 dest_port, BOOL is_udp, UINT32* out_proxy_id, DWORD pid_in, BOOL have_pid);

// Decision maker for new packets in the packet processor
RuleAction handle_new_connection_logic(
    int family,
    const UINT8 *src_addr,
    const UINT8 *dest_addr,
    UINT16 src_port,
    UINT16 dest_port,
    BOOL is_udp,
    UINT32* selected_proxy_id
);

#endif // NR_RULE_ENGINE_H