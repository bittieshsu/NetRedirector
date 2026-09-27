// Validation gate for NR_PidMap.c, run BEFORE wiring the map into NR_Utils.c.
//
// Two independent questions, both must pass:
//
//   A. SAFETY - does starting the map affect unrelated socket operations?
//      This drives the REAL pid_map_start(), not a hand-rolled handle, so the
//      flag set actually shipped is what gets tested. (An earlier version of
//      this probe opened the SOCKET layer with only WINDIVERT_FLAG_RECV_ONLY,
//      the flags the WinDivert docs list as mandatory for that layer, and every
//      bind() on the machine started failing with WSAEACCES. See
//      tests/probe_socket_layer_safety.c - WINDIVERT_FLAG_SNIFF is what makes
//      the layer observational, and NR_PidMap.c now always sets it.)
//
//   B. CORRECTNESS - with the map consuming events, do real flows resolve to the
//      same pid the authoritative GetExtendedTcpTable/GetExtendedUdpTable give?
//      The failure that matters is not a miss (a miss falls back to the table,
//      i.e. today's behaviour) but a CONFLICT: the map answers with a pid the
//      table disagrees with. Conflicts must be 0.
//
// Build & run (from NetRedirector\); needs WinDivert.dll in the cwd, so run
// from the repo root:
//   C:\ProgramData\mingw64\mingw64\bin\gcc -O2 -o tests\probe_pid_map.exe ^
//       tests\probe_pid_map.c NR_PidMap.c -I. WinDivert.lib -lws2_32 -liphlpapi
//   cd .. && NetRedirector\tests\probe_pid_map.exe

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "NR_PidMap.h"

// NR_PidMap.c calls log_message(); the real one lives in NetRedirector.c.
void log_message(const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    printf("    [log] ");
    vprintf(msg, ap);
    printf("\n");
    va_end(ap);
}

#define CYCLES   40
#define STALL_MS 1000

static double g_freq_qpc;

static double ms_since(LARGE_INTEGER t0)
{
    LARGE_INTEGER t1;
    QueryPerformanceCounter(&t1);
    return ((double)(t1.QuadPart - t0.QuadPart) * 1e3) / g_freq_qpc;
}

// socket() + bind(ephemeral) + close. Returns 0 or the WSA error.
static int bind_probe(char *why, int why_len)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        snprintf(why, why_len, "socket() wsa=%d", WSAGetLastError());
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        int e = WSAGetLastError();
        snprintf(why, why_len, "bind() wsa=%d", e);
        closesocket(s);
        return e;
    }
    closesocket(s);
    return 0;
}

// A fresh listener per phase. The first version of this test reused one listener
// for both phases and never called accept(), so the baseline phase filled the
// accept backlog and the second phase then failed every connect - which looked
// like the handle stalling sockets but was really the backlog.
static SOCKET make_listener(UINT16 *port_out)
{
    SOCKET lst = socket(AF_INET, SOCK_STREAM, 0);
    if (lst == INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = 0;
    if (bind(lst, (struct sockaddr *)&a, sizeof(a)) != 0) { closesocket(lst); return INVALID_SOCKET; }
    if (listen(lst, 512) != 0) { closesocket(lst); return INVALID_SOCKET; }
    int llen = sizeof(a);
    if (getsockname(lst, (struct sockaddr *)&a, &llen) != 0) { closesocket(lst); return INVALID_SOCKET; }
    *port_out = ntohs(a.sin_port);
    return lst;
}

// One socket()/connect()/accept()/close() cycle, reaping so the backlog never
// fills. Returns elapsed ms, or -1 on error.
static double one_cycle(SOCKET lst, UINT16 listen_port)
{
    LARGE_INTEGER t0;
    QueryPerformanceCounter(&t0);

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return -1;

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(listen_port);

    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        printf("    connect() failed wsa=%d after %.1f ms\n", WSAGetLastError(), ms_since(t0));
        closesocket(s);
        return -1;
    }
    SOCKET a_sock = accept(lst, NULL, NULL);
    if (a_sock != INVALID_SOCKET) closesocket(a_sock);
    closesocket(s);
    return ms_since(t0);
}

// Runs CYCLES cycles on its own listener. Returns 0 on success.
static int time_cycles(const char *label, double *mean_ms, double *max_ms)
{
    UINT16 port = 0;
    SOCKET lst = make_listener(&port);
    if (lst == INVALID_SOCKET) {
        printf("    %-34s cannot create listener (wsa=%d)\n", label, WSAGetLastError());
        return -1;
    }
    double total = 0, worst = 0;
    for (int i = 0; i < CYCLES; i++) {
        double ms = one_cycle(lst, port);
        if (ms < 0) { closesocket(lst); return -1; }
        total += ms;
        if (ms > worst) worst = ms;
        if (ms > STALL_MS) {
            printf("    %-34s cycle %d took %.1f ms -> STALLED\n", label, i, ms);
            closesocket(lst);
            return -1;
        }
    }
    closesocket(lst);
    *mean_ms = total / CYCLES;
    *max_ms  = worst;
    printf("    %-34s mean %7.3f ms   max %7.3f ms\n", label, *mean_ms, *max_ms);
    return 0;
}

static void bind_rounds(const char *label)
{
    int ok = 0;
    char first[96] = "";
    for (int i = 0; i < 12; i++) {
        char w[96] = "";
        if (bind_probe(w, sizeof(w)) == 0) ok++;
        else if (first[0] == 0) snprintf(first, sizeof(first), "%s", w);
    }
    printf("    %-34s %2d/12 bound%s%s\n", label, ok,
           (ok < 12) ? "   first: " : "", first);
}

// --- authoritative lookups, for the correctness test -----------------------

static DWORD table_pid_tcp(UINT16 local_port)
{
    DWORD size = 0, pid = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            != ERROR_INSUFFICIENT_BUFFER) return 0;
    MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!t) return 0;
    if (GetExtendedTcpTable(t, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            if (ntohs((UINT16)t->table[i].dwLocalPort) == local_port &&
                t->table[i].dwLocalAddr == inet_addr("127.0.0.1")) {
                pid = t->table[i].dwOwningPid;
                break;
            }
        }
    }
    free(t);
    return pid;
}

static DWORD table_pid_udp(UINT16 local_port)
{
    DWORD size = 0, pid = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0)
            != ERROR_INSUFFICIENT_BUFFER) return 0;
    MIB_UDPTABLE_OWNER_PID *t = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!t) return 0;
    if (GetExtendedUdpTable(t, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            if (ntohs((UINT16)t->table[i].dwLocalPort) == local_port &&
                t->table[i].dwLocalAddr == inet_addr("127.0.0.1")) {
                pid = t->table[i].dwOwningPid;
                break;
            }
        }
    }
    free(t);
    return pid;
}

int main(void)
{
    WSADATA wsa;
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_freq_qpc = (double)f.QuadPart;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("FATAL: WSAStartup\n"); return 2; }

    printf("PID map validation gate\n\n");

    // ================= A. SAFETY =================
    printf("A. Does starting the map affect unrelated socket operations?\n");
    double base_mean = 0, base_max = 0, map_mean = 0, map_max = 0;

    bind_rounds("control: no map");
    if (time_cycles("control: no map", &base_mean, &base_max) != 0) {
        printf("  baseline unusable; aborting\n");
        return 2;
    }

    printf("    pid_map_start() ... ");
    fflush(stdout);
    if (!pid_map_start()) {
        printf("FALSE\n  the feature is inert (lookups fall back); nothing to validate\n");
        return 1;
    }
    printf("OK\n");
    Sleep(300);

    bind_rounds("map running");
    int ok_cycles = (time_cycles("map running", &map_mean, &map_max) == 0);

    if (!ok_cycles) {
        printf("  VERDICT A: FAIL - starting the map breaks socket operations\n");
        pid_map_stop();
        return 1;
    }
    double ratio = (base_mean > 0.001) ? (map_mean / base_mean) : 0;
    printf("    ratio map/baseline = %.2fx\n", ratio);
    printf("  VERDICT A: %s\n\n", (ratio < 3.0) ? "PASS" : "REVIEW - measurable slowdown");

    // ================= B. CORRECTNESS =================
    printf("B. Does the map agree with GetExtendedTcpTable/UdpTable on real flows?\n");

    DWORD self = GetCurrentProcessId();
    int tcp_checked = 0, tcp_ok = 0, tcp_conflict = 0, tcp_miss = 0;
    int udp_checked = 0, udp_ok = 0, udp_conflict = 0, udp_miss = 0;

    UINT16 listen_port = 0;
    SOCKET listener = make_listener(&listen_port);
    if (listener == INVALID_SOCKET) { printf("  cannot create listener\n"); return 2; }
    printf("    listener on 127.0.0.1:%u\n", (unsigned)listen_port);

    // --- TCP: open connections, keep them alive, compare per local port ---
    #define N_FLOWS 24
    SOCKET tcp_socks[N_FLOWS];
    UINT16 tcp_ports[N_FLOWS];
    int    tcp_n = 0;
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = inet_addr("127.0.0.1");
    la.sin_port = htons(listen_port);

    for (int i = 0; i < N_FLOWS; i++) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, (struct sockaddr *)&la, sizeof(la)) != 0) { closesocket(s); continue; }
        struct sockaddr_in loc;
        int ll = sizeof(loc);
        if (getsockname(s, (struct sockaddr *)&loc, &ll) != 0) { closesocket(s); continue; }
        tcp_socks[tcp_n] = s;
        tcp_ports[tcp_n] = ntohs(loc.sin_port);
        tcp_n++;
    }
    // Reap the accepted side so the backlog cannot fill.
    for (int i = 0; i < tcp_n; i++) {
        SOCKET a = accept(listener, NULL, NULL);
        if (a != INVALID_SOCKET) closesocket(a);
    }
    printf("    opened %d TCP connections\n", tcp_n);

    // The event is generated on connect(); give the consumer a moment, then
    // check honestly - this is what the relay experiences.
    Sleep(200);

    for (int i = 0; i < tcp_n; i++) {
        DWORD map_pid = pid_map_lookup(FALSE, tcp_ports[i]);
        DWORD tbl_pid = table_pid_tcp(tcp_ports[i]);
        tcp_checked++;
        if (map_pid == 0) {
            tcp_miss++;
            printf("      TCP port %5u : map=MISS   table=%lu\n",
                   (unsigned)tcp_ports[i], (unsigned long)tbl_pid);
        } else if (tbl_pid != 0 && map_pid != tbl_pid) {
            tcp_conflict++;
            printf("      TCP port %5u : map=%lu CONFLICT table=%lu\n",
                   (unsigned)tcp_ports[i], (unsigned long)map_pid, (unsigned long)tbl_pid);
        } else {
            tcp_ok++;
        }
    }
    printf("    TCP: checked %d, agreed %d, missed %d, CONFLICT %d\n\n",
           tcp_checked, tcp_ok, tcp_miss, tcp_conflict);

    // --- UDP ---
    #define N_UDP 16
    SOCKET udp_socks[N_UDP];
    UINT16 udp_ports[N_UDP];
    int    udp_n = 0;

    for (int i = 0; i < N_UDP; i++) {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) continue;
        struct sockaddr_in loc;
        memset(&loc, 0, sizeof(loc));
        loc.sin_family = AF_INET;
        loc.sin_addr.s_addr = inet_addr("127.0.0.1");
        loc.sin_port = 0;
        if (bind(s, (struct sockaddr *)&loc, sizeof(loc)) != 0) { closesocket(s); continue; }
        if (sendto(s, "x", 1, 0, (struct sockaddr *)&la, sizeof(la)) == SOCKET_ERROR) {
            closesocket(s); continue;
        }
        int ll = sizeof(loc);
        if (getsockname(s, (struct sockaddr *)&loc, &ll) != 0) { closesocket(s); continue; }
        udp_socks[udp_n] = s;
        udp_ports[udp_n] = ntohs(loc.sin_port);
        udp_n++;
    }
    printf("    opened %d UDP sockets\n", udp_n);
    Sleep(200);

    for (int i = 0; i < udp_n; i++) {
        DWORD map_pid = pid_map_lookup(TRUE, udp_ports[i]);
        DWORD tbl_pid = table_pid_udp(udp_ports[i]);
        udp_checked++;
        if (map_pid == 0) {
            udp_miss++;
            printf("      UDP port %5u : map=MISS   table=%lu\n",
                   (unsigned)udp_ports[i], (unsigned long)tbl_pid);
        } else if (tbl_pid != 0 && map_pid != tbl_pid) {
            udp_conflict++;
            printf("      UDP port %5u : map=%lu CONFLICT table=%lu\n",
                   (unsigned)udp_ports[i], (unsigned long)map_pid, (unsigned long)tbl_pid);
        } else {
            udp_ok++;
        }
    }
    printf("    UDP: checked %d, agreed %d, missed %d, CONFLICT %d\n\n",
           udp_checked, udp_ok, udp_miss, udp_conflict);

    printf("    all answers should be this process (pid %lu)\n\n", (unsigned long)self);

    PID_MAP_STATS st;
    pid_map_get_stats(&st);
    printf("    event stream: events=%llu inserts=%llu removes=%llu ignored=%llu recv_errors=%llu\n",
           st.events, st.inserts, st.removes, st.ignored_events, st.recv_errors);
    printf("    lookups=%llu hits=%llu ambiguous=%llu\n\n", st.lookups, st.hits, st.ambiguous);

    int conflicts = tcp_conflict + udp_conflict;
    printf("VERDICT B: %s\n", conflicts == 0
           ? "PASS - zero conflicts; a miss only degrades to the existing table lookup"
           : "FAIL - the map disagreed with the authoritative table");

    for (int i = 0; i < tcp_n; i++) closesocket(tcp_socks[i]);
    for (int i = 0; i < udp_n; i++) closesocket(udp_socks[i]);
    closesocket(listener);
    pid_map_stop();
    WSACleanup();
    return (conflicts == 0) ? 0 : 1;
}
