// --- START OF FILE NR_PidMap.h ---
#ifndef NR_PID_MAP_H
#define NR_PID_MAP_H

#include "NR_Common.h"

// === Socket-event PID map ===
//
// Why this exists: NR_Utils.c resolves a packet's owning process by calling
// GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL). Measured on the dev machine
// (tests/bench_conn_lookup.c) that call costs ~650 us and the cost is FIXED,
// not per-row - IPv4 with 468 rows and IPv6 with 173 rows both land at ~640 us,
// and dropping the owner-PID field entirely (TCP_TABLE_BASIC_ALL) still costs
// 621 us. It is the single most expensive operation in the whole relay, ~5
// orders of magnitude above the entire per-packet path, and it runs at least
// once for every new connection. The per-socket cache in NR_Utils.c cannot help
// the FIRST lookup of a connection because its key contains local_port, which
// is brand new every time.
//
// WinDivert's SOCKET layer delivers socket lifecycle events that carry the
// owning ProcessId directly (verified by tests/probe_flow_layer.c on this
// build: FLOW and SOCKET layers both open and deliver pid-bearing events).
// Consuming them turns the per-connection lookup into a hash-table read.
//
// Fail-closed contract, in order of importance:
//   * A lookup that is not certain returns 0. The caller then falls back to
//     GetExtendedTcpTable, i.e. exactly today's behaviour. There is no path
//     where this map can answer "confidently wrong".
//   * Two different pids seen for the same (protocol, local port) mark the slot
//     AMBIGUOUS and it stops answering. Two sockets can legitimately share a
//     port (different local addresses, or a v4/v6 pair); we do not try to tell
//     them apart, because getting that wrong would silently mis-route traffic.
//   * Entries expire. Staleness is bounded by PID_MAP_TTL_MS, which only has to
//     outlive the gap between a connect() event and the first packet of that
//     connection.
//
// The whole feature is optional: if the handle cannot be opened, start() fails
// and every lookup returns 0, so the relay behaves exactly as before.

// Opens the SOCKET-layer handle and starts the consumer thread.
// Returns FALSE on failure - the caller should log and carry on.
BOOL pid_map_start(void);

// Stops the consumer thread and closes the handle. Safe to call when not
// started, and safe to call twice.
void pid_map_stop(void);

// (protocol, local port) -> pid. Returns 0 for any miss, expiry, ambiguity or
// "not started". Cheap enough for the new-connection path.
DWORD pid_map_lookup(BOOL is_udp, UINT16 local_port);

// Diagnostics. hits/misses describe lookups; the rest describe the event
// stream, which is how we tell "the map is empty" from "the layer is silent".
typedef struct {
    unsigned long long lookups;
    unsigned long long hits;
    unsigned long long ambiguous;      // refused to answer
    unsigned long long events;
    unsigned long long inserts;
    unsigned long long removes;
    unsigned long long ignored_events; // non-TCP/UDP, or an event we don't track
    unsigned long long recv_errors;
    BOOL               running;
    BOOL               handle_ok;
} PID_MAP_STATS;

void pid_map_get_stats(PID_MAP_STATS *out);

#endif // NR_PID_MAP_H
// --- END OF FILE NR_PidMap.h ---
