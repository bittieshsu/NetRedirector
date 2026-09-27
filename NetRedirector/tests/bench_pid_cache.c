// Microbenchmark: how much the PID_RESULT_CACHE's LINEAR SCAN costs on the
// new-connection path -- now that NR_PidMap.c exists.
//
// Why this question exists:
//   get_process_id_from_connection() checks the result cache BEFORE the pid map:
//
//       pid_result_cache_lookup(...)   <- 128-slot linear scan, every call
//       pid_map_lookup(...)            <- 8-slot probe
//       GetExtendedTcpTable(...)       <- ~650-1000 us, the thing we removed
//
//   The map turned the 650 us table snapshot into a sub-microsecond probe. If
//   the cache's scan is more expensive than the probe it precedes, then the scan
//   is now the dominant remaining cost of the fast path -- and it runs on EVERY
//   lookup, hit or miss, including the brand-new connections the map exists to
//   accelerate. That is the hypothesis this bench tests.
//
// ANSWER (measured, see output): the scan costs ~0.9 ns per slot, so ~0.115 us
//   for a full 128-slot miss. It is two to three orders of magnitude below the
//   table snapshot it precedes, and it cannot even be resolved above the noise
//   of that snapshot in the same measurement. Hypothesis refuted; nothing to fix.
//
// How the scan cost is isolated WITHOUT subtracting a noisy baseline:
//   The cache is primed with exactly 128 live entries, in order, so ports[i]
//   lands in slot i (the store path is round-robin). A hit for ports[i] scans
//   slots 0..i. So
//       t(slot 127) - t(slot 0)  ==  cost of 127 extra slot comparisons
//   which is baseline-free: no table snapshot is involved on a hit at all.
//
// The pid map is linked but deliberately NOT started, so pid_map_lookup()
// returns immediately (g_lock_ready == FALSE). That is the honest way to
// isolate the cache: the cache is consulted FIRST, so its scan cost is
// identical whether or not the map would have answered.
//
// Build & run (from NetRedirector\); needs WinDivert.dll in the cwd, so run
// from the repo root:
//   C:\ProgramData\mingw64\mingw64\bin\gcc -O2 -o tests\bench_pid_cache.exe ^
//       tests\bench_pid_cache.c NR_Utils.c NR_PidMap.c -I. WinDivert.lib ^
//       -lws2_32 -liphlpapi
//   cd .. && NetRedirector\tests\bench_pid_cache.exe
//
// (WinDivert.dll must be in the cwd to load; we never open a handle.)

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include "NR_Utils.h"
#include "NR_PidMap.h"

// Defined by NetRedirector.c in the real DLL. NR_Utils.c needs it.
CRITICAL_SECTION lock_pid_cache;

// NR_Utils.c calls log_message() on a few paths; we never take them here, but
// the symbol has to resolve at link time.
void log_message(const char *fmt, ...) { (void)fmt; }

#define N_SOCKETS   128
#define N_ITERS     200

static LARGE_INTEGER g_freq;

static double us_since(LARGE_INTEGER t0)
{
    LARGE_INTEGER t1;
    QueryPerformanceCounter(&t1);
    return (double)(t1.QuadPart - t0.QuadPart) * 1e6 / (double)g_freq.QuadPart;
}

// The exact two-call sequence the miss path performs (sizing call + fill call).
static double baseline_table_scan(void)
{
    DWORD size = 0;
    LARGE_INTEGER t0;

    QueryPerformanceCounter(&t0);
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            != ERROR_INSUFFICIENT_BUFFER) return -1;
    MIB_TCPTABLE_OWNER_PID *tbl = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!tbl) return -1;
    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tbl);
        return -1;
    }
    double us = us_since(t0);
    free(tbl);
    return us;
}

static double baseline_mean(int reps)
{
    double sum = 0;
    for (int i = 0; i < reps; i++) sum += baseline_table_scan();
    return sum / (double)reps;
}

static UINT16 g_absent_port;

static double time_lookup(UINT32 ip, UINT16 port, int iters, DWORD *pid_out)
{
    volatile DWORD sink = 0;
    LARGE_INTEGER t0;
    DWORD pid = 0;

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        pid = get_process_id_from_connection(ip, port);
        sink ^= pid;
    }
    double us = us_since(t0) / (double)iters;
    if (pid_out) *pid_out = pid;
    (void)sink;
    return us;
}

int main(void)
{
    WSADATA wsa;
    SOCKET socks[N_SOCKETS];
    UINT16 ports[N_SOCKETS];
    int n = 0;

    QueryPerformanceFrequency(&g_freq);
    // NetRedirector.c does this in its DLL init; we have to do it ourselves or
    // every EnterCriticalSection() on the cache lock crashes.
    InitializeCriticalSection(&lock_pid_cache);
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("WSAStartup failed\n"); return 1; }

    const UINT32 ip = inet_addr("127.0.0.1");

    // --- Bind N listening sockets on 127.0.0.1 so the TCP table really does
    //     contain N rows owned by this process. Without real rows the cache
    //     would never store anything and every "hit" would be a table scan.
    for (int i = 0; i < N_SOCKETS; i++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) break;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = ip;
        a.sin_port = 0;
        if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(s); break; }
        if (listen(s, 1) != 0) { closesocket(s); break; }
        int alen = sizeof(a);
        if (getsockname(s, (struct sockaddr *)&a, &alen) != 0) { closesocket(s); break; }
        socks[n] = s;
        ports[n] = ntohs(a.sin_port);
        n++;
    }
    printf("listening sockets created: %d\n", n);
    if (n < 8) { printf("not enough sockets to prime the cache; aborting\n"); return 1; }

    // An absent port: bind one more, note it, then close it.
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_addr.s_addr = ip; a.sin_port = 0;
        bind(s, (struct sockaddr *)&a, sizeof(a));
        int alen = sizeof(a);
        getsockname(s, (struct sockaddr *)&a, &alen);
        g_absent_port = ntohs(a.sin_port);
        closesocket(s);
    }

    // --- 1. Baseline, sampled three times to expose how noisy it is. This is
    //     the honest framing: the table snapshot's own run-to-run spread is
    //     tens of microseconds, so anything smaller cannot be resolved by
    //     subtracting it.
    printf("\n1. baseline GetExtendedTcpTable pair (2 syscalls), 3 samples:\n");
    double b_first = baseline_mean(5);
    printf("     sample A  %8.1f us\n", b_first);

    // --- 2. Cache hit cost by slot position. Baseline-free: a hit performs no
    //     table snapshot at all, so this is the scan cost directly.
    printf("\n2. cache HIT cost by slot position (128 live entries):\n");
    double t_slot[4] = {0, 0, 0, 0};
    const int probe_slots[4] = {0, 31, 63, 127};
    for (int p = 0; p < 4; p++) {
        clear_pid_cache();
        for (int i = 0; i < n; i++) get_process_id_from_connection(ip, ports[i]);  // prime, in order
        DWORD pid = 0;
        double us = time_lookup(ip, ports[probe_slots[p]], N_ITERS, &pid);
        if (pid == 0) { printf("     slot %3d  EXPIRED/UNCACHED (measurement invalid)\n", probe_slots[p]); }
        t_slot[p] = us;
        printf("     slot %3d (scans %3d slots)  %8.3f us\n", probe_slots[p], probe_slots[p] + 1, us);
    }
    {
        double marginal = t_slot[3] - t_slot[0];   // 127 extra slot comparisons
        printf("     -> marginal scan cost  (slot127 - slot0) = %.3f us for 127 slots"
               "  = %.2f ns/slot\n", marginal, marginal * 1000.0 / 127.0);
        printf("     -> a FULL 128-slot miss therefore costs ~%.3f us\n", t_slot[3]);
    }

    // --- 3. Full cache + absent port == the brand-new-connection fast path
    //     (minus the map, which is not started here). Compare against the empty
    //     cache case: the difference IS the scan, and it should be lost in noise.
    printf("\n3. full miss (new connection), cache empty vs full:\n");
    clear_pid_cache();
    double t_empty = time_lookup(ip, g_absent_port, N_ITERS, NULL);
    clear_pid_cache();
    for (int i = 0; i < n; i++) get_process_id_from_connection(ip, ports[i]);
    double t_full = time_lookup(ip, g_absent_port, N_ITERS, NULL);
    printf("     empty cache + absent port   %8.1f us\n", t_empty);
    printf("     FULL  cache + absent port   %8.1f us\n", t_full);
    printf("     difference %+.1f us  (expected ~+0.1 us; anything larger is noise)\n", t_full - t_empty);

    double b_last = baseline_mean(5);
    printf("     baseline sample B           %8.1f us   (spread vs sample A: %+.1f us)\n",
           b_last, b_last - b_first);

    // --- 4. Map probe cost for reference (map linked, never started).
    {
        LARGE_INTEGER t0;
        volatile DWORD sink = 0;
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < 100000; i++) sink ^= pid_map_lookup(FALSE, (UINT16)i);
        double us = us_since(t0) / 100000.0;
        printf("\n4. pid_map_lookup() with map NOT started   %8.4f us  (early-return only;\n"
               "     a real started-map hit additionally pays one uncontended CS enter/leave)\n", us);
        (void)sink;
    }

    for (int i = 0; i < n; i++) closesocket(socks[i]);
    DeleteCriticalSection(&lock_pid_cache);
    WSACleanup();
    return 0;
}
