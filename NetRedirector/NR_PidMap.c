// --- START OF FILE NR_PidMap.c ---
//
// Consumes WinDivert SOCKET-layer events and maintains
// (protocol, local_port) -> pid, so the new-connection path stops paying
// ~650 us for GetExtendedTcpTable. See NR_PidMap.h for the rationale and the
// fail-closed contract.

#include "NR_PidMap.h"

// Power of two. Sized for the sockets a busy desktop has open at once; the
// layer is system-wide, so this is deliberately generous (4096 * 32 B = 128 KB).
#define PID_MAP_SLOTS       4096
#define PID_MAP_MASK        (PID_MAP_SLOTS - 1)

// Linear probe window. A slot is placed in its home bucket or one of the next
// few, and lookups scan the whole window without early termination, so clearing
// a slot (on CLOSE) can never hide a later entry from a lookup.
#define PID_MAP_PROBE       8

// Only has to outlive the gap between the socket event and the first packet of
// that connection. Short on purpose: it is also the bound on how long a stale
// entry can survive a missed CLOSE event.
#define PID_MAP_TTL_MS      3000

#define PID_MAP_RECV_TIMEOUT_MS 1000

// The SOCKET layer's flags decide whether it BLOCKS socket operations, and the
// difference is not cosmetic.
//
// The WinDivert docs list the mandatory flags for this layer as
// WINDIVERT_FLAG_RECV_ONLY alone, and opening with exactly that succeeds - but
// it makes the layer BLOCKING: every filtered socket operation is held waiting
// for a verdict, and RECV_ONLY forbids ever sending one. Measured on the dev
// machine (tests/probe_socket_layer_safety.c, 12 bind() attempts per phase):
//
//     SOCKET + RECV_ONLY              : 0/12 bind() succeed, WSAEACCES (10013)
//     SOCKET + SNIFF | RECV_ONLY      : 12/12 bind() succeed
//     after closing the handle        : 12/12 (the effect is reversible)
//
// i.e. RECV_ONLY alone wedges socket creation for EVERY process on the machine
// for as long as the handle is open - a far worse outcome than the ~650 us
// lookup this file exists to avoid. WINDIVERT_FLAG_SNIFF is what makes the
// layer observational. Never drop it.
#define PID_MAP_LAYER_FLAGS (WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)

#define PID_MAP_FILTER      "tcp or udp"

typedef struct {
    DWORD stamp;      // GetTickCount of the last event for this socket; 0 = free
    UINT32 pid;
    UINT16 port;      // host byte order
    UINT8  is_udp;
    UINT8  ambiguous; // two different pids claimed this port - never answer
} PID_MAP_SLOT;

static PID_MAP_SLOT     g_slots[PID_MAP_SLOTS];
static CRITICAL_SECTION g_lock;
static BOOL             g_lock_ready = FALSE;

static HANDLE           g_handle   = INVALID_HANDLE_VALUE;
static HANDLE           g_thread   = NULL;
static HANDLE           g_stop     = NULL;    // manual-reset: "consumer, exit"
static volatile LONG    g_running  = 0;

static PID_MAP_STATS    g_stats;
static CRITICAL_SECTION g_stats_lock;
static BOOL             g_stats_lock_ready = FALSE;

// Hash on (protocol, port) only - deliberately NOT on the address. Two sockets
// sharing a port must land in the same probe window so the ambiguity check can
// see both. See pid_map_insert().
static UINT32 pid_map_home(BOOL is_udp, UINT16 port)
{
    UINT32 k = ((UINT32)port << 1) | (is_udp ? 1u : 0u);
    return (k * 2654435761u) >> 20 & PID_MAP_MASK;   // Knuth multiplicative
}

static void stats_bump(int field)
{
    if (!g_stats_lock_ready) return;
    EnterCriticalSection(&g_stats_lock);
    switch (field) {
    case 0: g_stats.lookups++;        break;
    case 1: g_stats.hits++;           break;
    case 2: g_stats.ambiguous++;      break;
    case 3: g_stats.events++;         break;
    case 4: g_stats.inserts++;        break;
    case 5: g_stats.removes++;        break;
    case 6: g_stats.ignored_events++; break;
    case 7: g_stats.recv_errors++;    break;
    }
    LeaveCriticalSection(&g_stats_lock);
}

static void pid_map_clear_locked(void)
{
    memset(g_slots, 0, sizeof(g_slots));
}

// --- map operations (all take g_lock) ---

DWORD pid_map_lookup(BOOL is_udp, UINT16 local_port)
{
    if (!g_lock_ready) return 0;

    UINT32 home = pid_map_home(is_udp, local_port);
    DWORD now = GetTickCount();
    DWORD result = 0;
    BOOL  saw_ambiguous = FALSE;

    EnterCriticalSection(&g_lock);
    for (int i = 0; i < PID_MAP_PROBE; i++) {
        PID_MAP_SLOT *s = &g_slots[(home + i) & PID_MAP_MASK];
        if (s->stamp == 0) continue;                       // free slot
        if ((now - s->stamp) > PID_MAP_TTL_MS) continue;   // expired
        if (s->port != local_port || s->is_udp != (UINT8)(is_udp ? 1 : 0)) continue;
        if (s->ambiguous) { saw_ambiguous = TRUE; continue; }
        result = s->pid;
        break;
    }
    LeaveCriticalSection(&g_lock);

    stats_bump(0);                       // lookups
    if (result != 0) stats_bump(1);      // hits
    else if (saw_ambiguous) stats_bump(2);
    return result;
}

static void pid_map_insert(BOOL is_udp, UINT16 local_port, UINT32 pid)
{
    if (pid == 0) return;

    UINT32 home = pid_map_home(is_udp, local_port);
    DWORD now = GetTickCount();
    UINT8 udp8 = (UINT8)(is_udp ? 1 : 0);

    EnterCriticalSection(&g_lock);

    int  target       = -1;
    int  free_slot    = -1;
    int  oldest_slot  = -1;
    DWORD oldest_stamp = 0xFFFFFFFF;

    for (int i = 0; i < PID_MAP_PROBE; i++) {
        PID_MAP_SLOT *s = &g_slots[(home + i) & PID_MAP_MASK];
        BOOL live = (s->stamp != 0) && ((now - s->stamp) <= PID_MAP_TTL_MS);

        if (live && s->port == local_port && s->is_udp == udp8) {
            if (s->pid == pid) {
                // Same socket reporting again (BIND then CONNECT, or a
                // re-announce): refresh and keep any ambiguity flag as-is.
                s->stamp = now;
                target = -2;                       // done, do not touch ambiguous
                break;
            }
            // A DIFFERENT pid for the same protocol+port. Either the port was
            // recycled before we saw a CLOSE, or two sockets genuinely share it.
            // We cannot tell which, so refuse to answer until it ages out.
            s->ambiguous = 1;
            s->pid = pid;
            s->stamp = now;
            target = -2;
            break;
        }
        if (live) {
            if (s->stamp < oldest_stamp) { oldest_stamp = s->stamp; oldest_slot = i; }
        } else if (free_slot < 0) {
            free_slot = i;
        }
    }

    if (target != -2) {
        target = (free_slot >= 0) ? free_slot
               : (oldest_slot >= 0) ? oldest_slot
               : 0;                                // window full of live others
        PID_MAP_SLOT *s = &g_slots[(home + target) & PID_MAP_MASK];
        s->stamp     = now;
        s->pid       = pid;
        s->port      = local_port;
        s->is_udp    = udp8;
        s->ambiguous = 0;
    }

    LeaveCriticalSection(&g_lock);
    stats_bump(4);
}

static void pid_map_remove(BOOL is_udp, UINT16 local_port, UINT32 pid)
{
    UINT32 home = pid_map_home(is_udp, local_port);
    UINT8 udp8 = (UINT8)(is_udp ? 1 : 0);

    EnterCriticalSection(&g_lock);
    for (int i = 0; i < PID_MAP_PROBE; i++) {
        PID_MAP_SLOT *s = &g_slots[(home + i) & PID_MAP_MASK];
        if (s->stamp == 0) continue;
        if (s->port != local_port || s->is_udp != udp8) continue;
        // Only clear it if the pid matches: a recycled port may already have
        // been claimed by a new socket, and a late CLOSE must not erase it.
        if (pid != 0 && s->pid != pid) continue;
        s->stamp = 0;
        s->ambiguous = 0;
        break;
    }
    LeaveCriticalSection(&g_lock);
    stats_bump(5);
}

// --- consumer thread ---

static DWORD WINAPI pid_map_worker(LPVOID arg)
{
    (void)arg;
    unsigned char buf[256];          // SOCKET-layer events carry no payload
    WINDIVERT_ADDRESS addr;
    UINT len = 0;

    while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
        len = 0;
        memset(&addr, 0, sizeof(addr));

        if (!WinDivertRecv(g_handle, buf, sizeof(buf), &len, &addr)) {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_HANDLE || err == ERROR_OPERATION_ABORTED) break;
            if (err == ERROR_NO_DATA) continue;      // queue empty, timeout
            stats_bump(7);
            continue;
        }

        if (addr.Layer != WINDIVERT_LAYER_SOCKET) { stats_bump(6); continue; }

        PWINDIVERT_DATA_SOCKET s = &addr.Socket;
        BOOL is_udp;
        if (s->Protocol == IPPROTO_TCP)      is_udp = FALSE;
        else if (s->Protocol == IPPROTO_UDP) is_udp = TRUE;
        else { stats_bump(6); continue; }

        stats_bump(3);   // events

        switch (addr.Event) {
        case WINDIVERT_EVENT_SOCKET_BIND:
        case WINDIVERT_EVENT_SOCKET_CONNECT:
        case WINDIVERT_EVENT_SOCKET_ACCEPT:
            // RemotePort is 0 for a listener; that is fine, we key on the local
            // side only.
            pid_map_insert(is_udp, s->LocalPort, s->ProcessId);
            break;
        case WINDIVERT_EVENT_SOCKET_CLOSE:
            pid_map_remove(is_udp, s->LocalPort, s->ProcessId);
            break;
        default:
            // SOCKET_LISTEN and anything else: not needed. The accepted socket
            // gets its own ACCEPT event, and bind() precedes listen().
            stats_bump(6);
            break;
        }
    }
    return 0;
}

// --- lifecycle ---

BOOL pid_map_start(void)
{
    if (!g_lock_ready) {
        InitializeCriticalSection(&g_lock);
        g_lock_ready = TRUE;
    }
    if (!g_stats_lock_ready) {
        InitializeCriticalSection(&g_stats_lock);
        g_stats_lock_ready = TRUE;
    }
    if (InterlockedCompareExchange(&g_running, 1, 1) == 1) return TRUE;   // already up

    memset(&g_stats, 0, sizeof(g_stats));
    pid_map_clear_locked();

    // [Added] WinDivertOpen validates layer AND flags together. The SOCKET layer
    // mandates WINDIVERT_FLAG_RECV_ONLY; omitting it fails with
    // ERROR_INVALID_PARAMETER (87), which looks like "unsupported layer".
    SetLastError(0);
    g_handle = WinDivertOpen(PID_MAP_FILTER, WINDIVERT_LAYER_SOCKET, 0, PID_MAP_LAYER_FLAGS);
    if (g_handle == INVALID_HANDLE_VALUE) {
        g_stats.handle_ok = FALSE;
        log_message("PID map: socket-layer handle unavailable (%lu); "
                    "process lookup stays on GetExtendedTcpTable", GetLastError());
        return FALSE;
    }
    g_stats.handle_ok = TRUE;

    // Bounded queue: if the consumer ever falls behind we would rather lose
    // events (-> cache miss -> authoritative fallback) than grow the queue and
    // let the driver hold memory for us.
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
    WinDivertSetParam(g_handle, WINDIVERT_PARAM_QUEUE_TIME, PID_MAP_RECV_TIMEOUT_MS);

    g_stop = CreateEvent(NULL, TRUE, FALSE, NULL);   // manual reset
    if (g_stop == NULL) {
        WinDivertClose(g_handle);
        g_handle = INVALID_HANDLE_VALUE;
        g_stats.handle_ok = FALSE;
        return FALSE;
    }

    InterlockedExchange(&g_running, 1);
    g_stats.running = TRUE;
    g_thread = CreateThread(NULL, 0, pid_map_worker, NULL, 0, NULL);
    if (g_thread == NULL) {
        InterlockedExchange(&g_running, 0);
        g_stats.running = FALSE;
        CloseHandle(g_stop);
        g_stop = NULL;
        WinDivertClose(g_handle);
        g_handle = INVALID_HANDLE_VALUE;
        g_stats.handle_ok = FALSE;
        return FALSE;
    }

    log_message("PID map: socket-event cache up (layer=SOCKET, ttl=%d ms)",
                PID_MAP_TTL_MS);
    return TRUE;
}

void pid_map_stop(void)
{
    InterlockedExchange(&g_running, 0);
    g_stats.running = FALSE;

    if (g_stop != NULL) SetEvent(g_stop);
    if (g_handle != INVALID_HANDLE_VALUE) {
        // Unblocks WinDivertRecv in the consumer even if it is parked.
        WinDivertClose(g_handle);
        g_handle = INVALID_HANDLE_VALUE;
    }
    if (g_thread != NULL) {
        WaitForSingleObject(g_thread, 5000);
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    if (g_stop != NULL) { CloseHandle(g_stop); g_stop = NULL; }

    if (g_lock_ready) {
        EnterCriticalSection(&g_lock);
        pid_map_clear_locked();
        LeaveCriticalSection(&g_lock);
    }
    g_stats.handle_ok = FALSE;
}

void pid_map_get_stats(PID_MAP_STATS *out)
{
    if (out == NULL) return;
    if (!g_stats_lock_ready) { memset(out, 0, sizeof(*out)); return; }
    EnterCriticalSection(&g_stats_lock);
    *out = g_stats;
    out->running   = (InterlockedCompareExchange(&g_running, 1, 1) == 1);
    LeaveCriticalSection(&g_stats_lock);
}
// --- END OF FILE NR_PidMap.c ---
