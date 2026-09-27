// Microbenchmark: cost of the two things the NEW-CONNECTION path does before
// it can classify a packet.
//
//   1. The process-id lookup, which on a cache miss snapshots the WHOLE system
//      TCP/UDP table (GetExtendedTcpTable + malloc + copy).
//   2. The connection-list walk behind is_connection_tracked()/get_connection().
//      This bench links the REAL NR_State.c so the numbers include the
//      critical section, not a synthetic stand-in.
//
// Why this matters: NR_Core.c's "new connection" branch runs
// is_connection_tracked() (walk 1, miss) and then handle_new_connection_logic()
// which itself calls get_connection() (walk 2, guaranteed miss, identical key).
// And when the pid lookup cannot resolve a process, NR_Utils.c deliberately
// does NOT cache the failure ("pid == 0 return;"), so handle_new_connection_logic
// and the check_process_rule() it then calls each snapshot the table again.
//
// Build & run (from NetRedirector\):
//   C:\ProgramData\mingw64\mingw64\bin\gcc -O2 -o tests\bench_conn_lookup.exe ^
//       tests\bench_conn_lookup.c NR_State.c -I. -lws2_32 -liphlpapi
//   tests\bench_conn_lookup.exe

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include "NR_State.h"

// NR_State.c expects these to be defined by the DLL entry unit (NetRedirector.c).
CRITICAL_SECTION lock_connections;
CRITICAL_SECTION lock_udp;
CRITICAL_SECTION lock_proxies;
CRITICAL_SECTION lock_logged;

static LARGE_INTEGER g_freq;

static double us_per(LARGE_INTEGER t0, LARGE_INTEGER t1, int iters)
{
    return ((double)(t1.QuadPart - t0.QuadPart) * 1e6) / g_freq.QuadPart / iters;
}

static double ns_per(LARGE_INTEGER t0, LARGE_INTEGER t1, int iters)
{
    return ((double)(t1.QuadPart - t0.QuadPart) * 1e9) / g_freq.QuadPart / iters;
}

// --- 1. Raw table snapshots ------------------------------------------------

static void bench_tcp_table_v4(int iters, double *us, DWORD *entries)
{
    DWORD size = 0, n = 0;
    LARGE_INTEGER t0, t1;
    volatile DWORD sink = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            != ERROR_INSUFFICIENT_BUFFER) { *us = -1; return; }
    MIB_TCPTABLE_OWNER_PID *tbl = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!tbl) { *us = -1; return; }

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        DWORD s = size;
        if (GetExtendedTcpTable(tbl, &s, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            sink += tbl->dwNumEntries;
    }
    QueryPerformanceCounter(&t1);

    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        n = tbl->dwNumEntries;
    *entries = n;
    *us = us_per(t0, t1, iters);
    free(tbl);
    (void)sink;
}

static void bench_udp_table_v4(int iters, double *us, DWORD *entries)
{
    DWORD size = 0, n = 0;
    LARGE_INTEGER t0, t1;
    volatile DWORD sink = 0;

    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0)
            != ERROR_INSUFFICIENT_BUFFER) { *us = -1; return; }
    MIB_UDPTABLE_OWNER_PID *tbl = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!tbl) { *us = -1; return; }

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        DWORD s = size;
        if (GetExtendedUdpTable(tbl, &s, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
            sink += tbl->dwNumEntries;
    }
    QueryPerformanceCounter(&t1);

    if (GetExtendedUdpTable(tbl, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        n = tbl->dwNumEntries;
    *entries = n;
    *us = us_per(t0, t1, iters);
    free(tbl);
    (void)sink;
}

static void bench_tcp_table_v6(int iters, double *us, DWORD *entries)
{
    DWORD size = 0, n = 0;
    LARGE_INTEGER t0, t1;
    volatile DWORD sink = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
            != ERROR_INSUFFICIENT_BUFFER) { *us = -1; return; }
    MIB_TCP6TABLE_OWNER_PID *tbl = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
    if (!tbl) { *us = -1; return; }

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        DWORD s = size;
        if (GetExtendedTcpTable(tbl, &s, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            sink += tbl->dwNumEntries;
    }
    QueryPerformanceCounter(&t1);

    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        n = tbl->dwNumEntries;
    *entries = n;
    *us = us_per(t0, t1, iters);
    free(tbl);
    (void)sink;
}

// --- 1b. Which table class, and what a table-level cache would cost --------

// Snapshot any TCP table class, so the cost can be attributed to (a) the copy,
// (b) the per-row owner-PID resolution, (c) the listener rows.
static void bench_tcp_class(int iters, ULONG table_class, const char *label,
                            double *us, DWORD *entries)
{
    DWORD size = 0, n = 0;
    LARGE_INTEGER t0, t1;
    volatile DWORD sink = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, table_class, 0)
            != ERROR_INSUFFICIENT_BUFFER) { *us = -1; return; }
    void *tbl = malloc(size);
    if (!tbl) { *us = -1; return; }

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        DWORD s = size;
        if (GetExtendedTcpTable(tbl, &s, FALSE, AF_INET, table_class, 0) == NO_ERROR)
            sink += *(DWORD *)tbl;   // dwNumEntries is the first field in all classes
    }
    QueryPerformanceCounter(&t1);

    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET, table_class, 0) == NO_ERROR)
        n = *(DWORD *)tbl;
    *entries = n;
    *us = us_per(t0, t1, iters);
    free(tbl);
    (void)sink;
    (void)label;
}

// What a table-level cache would pay per lookup: scan an already-copied
// OWNER_PID_ALL table in user mode for a (local_addr, local_port) match.
static double bench_cached_rescan(int iters, DWORD *entries)
{
    DWORD size = 0;
    LARGE_INTEGER t0, t1;
    volatile DWORD sink = 0;

    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            != ERROR_INSUFFICIENT_BUFFER) return -1;
    MIB_TCPTABLE_OWNER_PID *tbl = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!tbl) return -1;
    if (GetExtendedTcpTable(tbl, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        free(tbl); return -1;
    }
    *entries = tbl->dwNumEntries;

    // Target the last row: worst case for the scan.
    DWORD want_addr = tbl->table[tbl->dwNumEntries - 1].dwLocalAddr;
    UINT16 want_port = (UINT16)tbl->table[tbl->dwNumEntries - 1].dwLocalPort;

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        DWORD pid = 0;
        for (DWORD r = 0; r < tbl->dwNumEntries; r++) {
            if (tbl->table[r].dwLocalAddr == want_addr &&
                (UINT16)tbl->table[r].dwLocalPort == want_port) {
                pid = tbl->table[r].dwOwningPid;
                break;
            }
        }
        sink += pid;
    }
    QueryPerformanceCounter(&t1);
    free(tbl);
    (void)sink;
    return us_per(t0, t1, iters);
}

// --- 2. Real connection-list walks ----------------------------------------

static void seed_list(int count)
{
    UINT8 src[16] = {0}, dst[16] = {0};
    src[0] = 192; src[1] = 168; src[2] = 1; src[3] = 10;
    dst[0] = 1; dst[1] = 1; dst[2] = 1; dst[3] = 1;
    clear_connections();
    for (int i = 0; i < count; i++) {
        // Unique src_port per entry; all share one destination.
        add_connection((UINT16)(40000 + i), AF_INET, src, dst, 443,
                       (i & 1) ? 0 : 1, (i & 1) ? RULE_ACTION_DIRECT : RULE_ACTION_PROXY, FALSE);
    }
}

// The exact pattern of NR_Core.c case 2 (tracked outbound): is_connection_tracked
// then get_connection on the same key.
static double bench_case2_hit(int iters)
{
    LARGE_INTEGER t0, t1;
    UINT8 dst[16] = {0};
    dst[0] = 1; dst[1] = 1; dst[2] = 1; dst[3] = 1;
    // Entry added first sits at the TAIL (add_connection pushes to front), so
    // this is the worst case: walk 1 traverses the whole list.
    UINT16 port = 40000;
    volatile int sink = 0;

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        if (is_connection_tracked(port, AF_INET, dst)) {
            UINT32 proxy_id = 0;
            get_connection(port, AF_INET, dst, NULL, NULL, NULL, &proxy_id, NULL);
            sink += (int)proxy_id;
        }
    }
    QueryPerformanceCounter(&t1);
    return ns_per(t0, t1, iters);
}

// Case 3 (new connection): is_connection_tracked MISSES, then
// handle_new_connection_logic() calls get_connection() with the same key -
// a guaranteed second full miss.
static double bench_case3_miss(int iters)
{
    LARGE_INTEGER t0, t1;
    UINT8 dst[16] = {0};
    dst[0] = 8; dst[1] = 8; dst[2] = 8; dst[3] = 8;   // absent from the list
    UINT16 port = 55555;                              // absent from the list
    volatile int sink = 0;

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        if (!is_connection_tracked(port, AF_INET, dst)) {
            UINT32 proxy_id = 0;
            RuleAction action = RULE_ACTION_DIRECT;
            get_connection(port, AF_INET, dst, NULL, NULL, NULL, &proxy_id, &action);
            sink += (int)action;
        }
    }
    QueryPerformanceCounter(&t1);
    return ns_per(t0, t1, iters);
}

// Single walk, for comparison: one get_connection() miss.
static double bench_single_miss(int iters)
{
    LARGE_INTEGER t0, t1;
    UINT8 dst[16] = {0};
    dst[0] = 8; dst[1] = 8; dst[2] = 8; dst[3] = 8;
    UINT16 port = 55555;
    volatile int sink = 0;

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iters; i++) {
        UINT32 proxy_id = 0;
        sink += get_connection(port, AF_INET, dst, NULL, NULL, NULL, &proxy_id, NULL);
    }
    QueryPerformanceCounter(&t1);
    return ns_per(t0, t1, iters);
}

int main(void)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&lock_connections);
    InitializeCriticalSection(&lock_udp);
    InitializeCriticalSection(&lock_proxies);
    InitializeCriticalSection(&lock_logged);
    QueryPerformanceFrequency(&g_freq);

    printf("NetRedirector connection-setup microbenchmark\n");
    printf("(real NR_State.c linked; walks include the critical section)\n\n");

    // ---- 1. Table snapshots ----
    double tcp4_us, udp4_us, tcp6_us;
    DWORD tcp4_n, udp4_n, tcp6_n;
    bench_tcp_table_v4(2000, &tcp4_us, &tcp4_n);
    bench_udp_table_v4(2000, &udp4_us, &udp4_n);
    bench_tcp_table_v6(2000, &tcp6_us, &tcp6_n);

    printf("System table snapshots (the whole table is copied out of the kernel):\n");
    printf("  %-46s %9.1f us/op   (%lu entries)\n",
           "GetExtendedTcpTable  IPv4 OWNER_PID_ALL", tcp4_us, (unsigned long)tcp4_n);
    printf("  %-46s %9.1f us/op   (%lu entries)\n",
           "GetExtendedUdpTable  IPv4 OWNER_PID", udp4_us, (unsigned long)udp4_n);
    printf("  %-46s %9.1f us/op   (%lu entries)\n\n",
           "GetExtendedTcpTable  IPv6 OWNER_PID_ALL", tcp6_us, (unsigned long)tcp6_n);

    // ---- 1b. Cost attribution + table-cache potential ----
    double basic_us, conn_us, rescan_us;
    DWORD basic_n, conn_n, rescan_n;
    bench_tcp_class(2000, TCP_TABLE_BASIC_ALL, "BASIC_ALL", &basic_us, &basic_n);
    bench_tcp_class(2000, TCP_TABLE_OWNER_PID_CONNECTIONS, "OWNER_PID_CONNECTIONS", &conn_us, &conn_n);
    rescan_us = bench_cached_rescan(200000, &rescan_n);

    printf("Where the 575 us goes, and what a table-level cache would cost:\n");
    printf("  %-46s %9.1f us/op  (%lu rows)\n",
           "TCP_TABLE_BASIC_ALL  (no owner pid)", basic_us, (unsigned long)basic_n);
    printf("  %-46s %9.1f us/op  (%lu rows)\n",
           "TCP_TABLE_OWNER_PID_CONNECTIONS", conn_us, (unsigned long)conn_n);
    printf("  %-46s %9.1f us/op  (%lu rows)\n",
           "TCP_TABLE_OWNER_PID_ALL", tcp4_us, (unsigned long)tcp4_n);
    printf("  %-46s %9.3f us/op  (%lu rows)\n",
           "user-mode rescan of an already-copied table", rescan_us, (unsigned long)rescan_n);
    if (basic_us > 0 && rescan_us > 0) {
        printf("\n  owner-PID resolution accounts for %.0f%% of the snapshot;\n",
               100.0 * (tcp4_us - basic_us) / tcp4_us);
        printf("  a table-level cache would cut a lookup by %.0fx (%.1f us -> %.3f us).\n",
               tcp4_us / rescan_us, tcp4_us, rescan_us);
    }
    printf("\n");

    // ---- 2. List walks ----
    const int sizes[] = { 32, 128, 512, 2048 };
    printf("Connection-list walks (one entry per tracked flow):\n");
    printf("  %7s %14s %14s %16s %14s\n",
           "entries", "single miss", "case3 (2x miss)", "case2 hit(1 full+1)", "double/miss");

    for (int i = 0; i < 4; i++) {
        int n = sizes[i];
        seed_list(n);
        int iters = (n <= 512) ? 200000 : 50000;
        double one = bench_single_miss(iters);
        double two = bench_case3_miss(iters);
        double hit = bench_case2_hit(iters);
        printf("  %7d %11.0f ns %11.0f ns %13.0f ns %11.2fx\n",
               n, one, two, hit, (one > 0) ? (two / one) : 0.0);
    }
    clear_connections();

    // ---- 3. What the new-connection path pays when the pid cannot be resolved ----
    printf("\nNew-connection path when the pid lookup MISSES (pid == 0):\n");
    printf("  NR_Utils.c does not cache a failed lookup, so the same socket is\n");
    printf("  snapshotted twice - once in handle_new_connection_logic(), once in\n");
    printf("  the check_process_rule() it falls through to.\n\n");
    printf("  %-46s %9.1f us\n", "1 x GetExtendedTcpTable (IPv4)", tcp4_us);
    printf("  %-46s %9.1f us\n", "2 x GetExtendedTcpTable (IPv4)  <-- actual",
           tcp4_us * 2.0);
    printf("  %-46s %9.1f us\n", "1 x GetExtendedUdpTable (IPv4, UDP path)", udp4_us);
    printf("  %-46s %9.1f us\n", "2 x GetExtendedUdpTable (IPv4)  <-- actual",
           udp4_us * 2.0);

    printf("\n  For a page opening 100 connections that all miss the pid cache:\n");
    printf("    TCP: %6.1f ms of pure duplicate work\n", tcp4_us * 100.0 / 1000.0);
    printf("    UDP: %6.1f ms of pure duplicate work\n", udp4_us * 100.0 / 1000.0);

    DeleteCriticalSection(&lock_connections);
    WSACleanup();
    return 0;
}
