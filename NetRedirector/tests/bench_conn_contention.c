// Microbenchmark: does lock_connections actually limit throughput?
//
// The existing bench_conn_lookup.c measures a SINGLE-THREADED walk. That number
// cannot answer the question that matters, because the cost has three parts and
// they need different experiments:
//
//   (a) the O(active-flows) list scan      -> measured by varying M
//   (b) the exclusive lock on EVERY packet -> measured by varying thread count
//   (c) the move-to-front WRITE on every HIT -> measured by mode 0 vs mode 1
//
// Why (c) matters: is_connection_tracked() unlinks and relinks the matched node
// on every hit. That turns a logically-read-only lookup into a write, so the
// lock cannot be shared and every worker dirties the same cache line. If the
// throughput curve is flat (or falls) as threads are added, the lock - not the
// scan length - is the bottleneck, and a hash index alone would NOT fix it.
//
// Why the scan is O(M) and not O(N): move-to-front is self-organising, so the
// flows actually being touched cluster at the head. The list can hold N=1024
// entries while the walk only ever covers the M flows in flight. This bench
// therefore separates N (entries seeded) from M (flows each thread cycles).
//
// Build & run (from NetRedirector\):
//   C:\ProgramData\mingw64\mingw64\bin\gcc -O2 -o tests\bench_conn_contention.exe ^
//       tests\bench_conn_contention.c NR_State.c -I. -lws2_32 -liphlpapi
//   tests\bench_conn_contention.exe

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
CRITICAL_SECTION lock_pid_cache;

// NR_State.c calls log_message() in a few paths; the bench never reaches them.
void log_message(const char *msg, ...) { (void)msg; }

#define MAX_ENTRIES  4096
#define MAX_THREADS  16

static UINT16 g_ports[MAX_ENTRIES];
static UINT8  g_dst[16];
static int    g_n_entries = 0;

// --- seeding ---------------------------------------------------------------

// Seed N entries, one per unique src_port, all sharing one destination.
// add_connection() pushes to the FRONT, so the ports seeded first end up at the
// TAIL - the worst case for a cold walk.
static void seed(int n)
{
    UINT8 src[16] = {0};
    src[0] = 192; src[1] = 168; src[2] = 1; src[3] = 10;
    memset(g_dst, 0, sizeof(g_dst));
    g_dst[0] = 1; g_dst[1] = 1; g_dst[2] = 1; g_dst[3] = 1;

    clear_connections();
    for (int i = 0; i < n; i++) {
        g_ports[i] = (UINT16)(40000 + i);
        add_connection(g_ports[i], AF_INET, src, g_dst, 443,
                       (i & 1) ? 0 : 1,
                       (i & 1) ? RULE_ACTION_DIRECT : RULE_ACTION_PROXY, FALSE);
    }
    g_n_entries = n;
}

// --- worker ----------------------------------------------------------------

// mode 0: the REAL is_connection_tracked()  (global lock + move-to-front write)
// mode 1: identical scan under the same global lock, but NO move-to-front
//         -> isolates the cost of the write
typedef struct {
    int  tid;
    int  n_threads;
    int  mode;
    int  active_flows;      // M: how many distinct flows this thread cycles
    int  disjoint;          // 1 = this thread uses its own slice of the M flows
    int  stride;            // 0 = cycle M sequentially, else walk with a stride
    long iters;
    volatile LONG *go;
    long long visited;      // nodes touched (mode 2 only)
} WORKER;

static int g_disjoint = 0;   // read by run() when spawning workers

static DWORD WINAPI worker_proc(LPVOID param)
{
    WORKER *w = (WORKER *)param;
    UINT8 dst[16];
    memcpy(dst, g_dst, sizeof(dst));

    // Disjoint mode mirrors the real dispatch: NR_Core.c hashes a packet's
    // 5-tuple to a worker, so different workers normally carry different flows.
    // Shared mode (all workers on the same flows) is the worst case.
    int span = w->disjoint
             ? (w->active_flows / w->n_threads)
             : w->active_flows;
    if (span < 1) span = 1;
    int base = w->disjoint ? (w->tid * span) : 0;

    while (*(w->go) == 0) Sleep(0);

    long long visited = 0;
    for (long i = 0; i < w->iters; i++) {
        int idx = base + (int)((i + (w->disjoint ? 0 : w->tid)) % span);
        UINT16 port = g_ports[idx];

        if (w->mode == 0) {
            is_connection_tracked(port, AF_INET, dst);
        } else if (w->mode == 1) {
            // Read-only walk: same predicate, same lock, but no relink.
            int n = 4;
            EnterCriticalSection(&lock_connections);
            CONNECTION_INFO *c = connection_list;
            while (c != NULL) {
                if (c->src_port == port && !c->is_udp && c->family == AF_INET &&
                    memcmp(c->orig_dest_addr, dst, n) == 0) break;
                c = c->next;
            }
            LeaveCriticalSection(&lock_connections);
        } else if (w->mode == 3) {
            // The CURRENT NR_Core.c case-2 sequence: a BOOL-only walk, then a
            // second walk with the SAME key just to fetch proxy_id. Two lock
            // acquisitions and two move-to-front writes per packet.
            UINT32 proxy_id = 0;
            if (is_connection_tracked(port, AF_INET, dst)) {
                get_connection(port, AF_INET, dst, NULL, NULL, NULL, &proxy_id, NULL);
            }
            visited += proxy_id;
        } else if (w->mode == 4) {
            // Proposed: ONE walk returns both tracked-ness and proxy_id.
            // get_connection() uses the identical predicate to
            // is_connection_tracked() (same src_port + !is_udp + family +
            // memcmp on orig_dest_addr), so `if (get_connection(...))` is
            // semantically the same test - and it also refreshes
            // last_activity, which is_connection_tracked() does not.
            UINT32 proxy_id = 0;
            if (get_connection(port, AF_INET, dst, NULL, NULL, NULL, &proxy_id, NULL)) {
                visited += proxy_id;
            }
        } else {
            // mode 2: count nodes, then apply the real move-to-front by hand so
            // the steady-state ordering matches mode 0. Not used for timing.
            int n = 4;
            EnterCriticalSection(&lock_connections);
            CONNECTION_INFO *c = connection_list;
            CONNECTION_INFO *prev = NULL;
            while (c != NULL) {
                visited++;
                if (c->src_port == port && !c->is_udp && c->family == AF_INET &&
                    memcmp(c->orig_dest_addr, dst, n) == 0) {
                    if (prev != NULL) {
                        prev->next = c->next;
                        c->next = connection_list;
                        connection_list = c;
                    }
                    break;
                }
                prev = c;
                c = c->next;
            }
            LeaveCriticalSection(&lock_connections);
        }
    }
    w->visited = visited;
    return 0;
}

// --- driver ----------------------------------------------------------------

typedef struct { double ns_per_op; double ops_per_sec; } RESULT;

static double now_sec(void)
{
    LARGE_INTEGER f, t;
    static LARGE_INTEGER freq;
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    (void)f;
    return (double)t.QuadPart / (double)freq.QuadPart;
}

static RESULT run(int n_threads, int mode, int active_flows, long iters_per_thread)
{
    HANDLE th[MAX_THREADS];
    WORKER w[MAX_THREADS];
    volatile LONG go = 0;
    RESULT r = {0, 0};

    for (int i = 0; i < n_threads; i++) {
        w[i].tid = i;
        w[i].n_threads = n_threads;
        w[i].mode = mode;
        w[i].active_flows = active_flows;
        w[i].disjoint = g_disjoint;
        w[i].iters = iters_per_thread;
        w[i].go = &go;
        w[i].visited = 0;
        th[i] = CreateThread(NULL, 0, worker_proc, &w[i], 0, NULL);
        if (th[i] == NULL) { printf("  CreateThread failed\n"); return r; }
    }

    // Give the threads a moment to reach the spin, then release them together.
    Sleep(50);
    double t0 = now_sec();
    InterlockedExchange(&go, 1);

    WaitForMultipleObjects(n_threads, th, TRUE, INFINITE);
    double t1 = now_sec();

    for (int i = 0; i < n_threads; i++) CloseHandle(th[i]);

    double total_ops = (double)iters_per_thread * n_threads;
    double secs = t1 - t0;
    r.ns_per_op = (secs * 1e9) / total_ops;
    r.ops_per_sec = total_ops / secs;
    return r;
}

// Pre-organise the list so the M hot flows sit at the head, exactly as they
// would after a few packets in production. Without this, mode 1 (read-only)
// would start with the hot flows at the TAIL and never migrate - which measures
// "no self-organisation", not "no write". Both modes are warmed identically.
static void warm_hot_flows(int m)
{
    UINT8 dst[16];
    memcpy(dst, g_dst, sizeof(dst));
    for (int pass = 0; pass < 3; pass++)
        for (int i = 0; i < m; i++)
            is_connection_tracked(g_ports[i], AF_INET, dst);
}

// run() with the shared/disjoint dispatch choice made explicit.
static RESULT run2(int n_threads, int mode, int active_flows, long iters, int disjoint)
{
    g_disjoint = disjoint;
    RESULT r = run(n_threads, mode, active_flows, iters);
    g_disjoint = 0;
    return r;
}

static double avg_walk(int n_threads, int active_flows, long iters_per_thread)
{
    HANDLE th[MAX_THREADS];
    WORKER w[MAX_THREADS];
    volatile LONG go = 0;

    for (int i = 0; i < n_threads; i++) {
        w[i].tid = i; w[i].n_threads = n_threads; w[i].mode = 2;
        w[i].active_flows = active_flows; w[i].iters = iters_per_thread;
        w[i].disjoint = 0; w[i].stride = 0;
        w[i].go = &go; w[i].visited = 0;
        th[i] = CreateThread(NULL, 0, worker_proc, &w[i], 0, NULL);
    }
    Sleep(50);
    InterlockedExchange(&go, 1);
    WaitForMultipleObjects(n_threads, th, TRUE, INFINITE);

    long long total = 0;
    for (int i = 0; i < n_threads; i++) { total += w[i].visited; CloseHandle(th[i]); }
    return (double)total / ((double)iters_per_thread * n_threads);
}

int main(void)
{
    WSADATA wsa;
    SYSTEM_INFO si;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    InitializeCriticalSection(&lock_connections);
    InitializeCriticalSection(&lock_udp);
    InitializeCriticalSection(&lock_proxies);
    InitializeCriticalSection(&lock_logged);
    InitializeCriticalSection(&lock_pid_cache);
    GetSystemInfo(&si);

    printf("NetRedirector connection-table contention bench\n");
    printf("(real NR_State.c linked; walks include the critical section)\n");
    printf("CPU cores: %lu\n\n", (unsigned long)si.dwNumberOfProcessors);

    const int thread_counts[] = { 1, 2, 3, 4, 6, 8 };
    const int n_thread_counts = 6;
    const long ITERS = 2000000;

    // ---- A. Thread scaling, hot working set (the per-packet case) ----
    // N = 1024 tracked entries, M = 64 flows in flight. Every lookup HITS.
    printf("=== A. Per-packet lookup: does throughput scale with threads? ===\n");
    printf("N = 1024 tracked entries, M = 64 flows in flight, all HITS\n\n");
    printf("  %7s | %12s %12s | %12s %12s\n",
           "threads", "mode0 ns/op", "mode0 ops/s", "mode1 ns/op", "mode1 ops/s");
    printf("  %7s | %-12s %-12s | %-12s %-12s\n",
           "", "(lock+MTF)", "(write)", "(lock only)", "(no write)");

    double a_ns[8], a_ops[8], b_ns[8], b_ops[8];
    for (int i = 0; i < n_thread_counts; i++) {
        int t = thread_counts[i];
        seed(1024); warm_hot_flows(64);
        RESULT a = run(t, 0, 64, ITERS);
        seed(1024); warm_hot_flows(64);
        RESULT b = run(t, 1, 64, ITERS);
        a_ns[i] = a.ns_per_op; a_ops[i] = a.ops_per_sec;
        b_ns[i] = b.ns_per_op; b_ops[i] = b.ops_per_sec;
        printf("  %7d | %12.1f %12.0f | %12.1f %12.0f\n",
               t, a.ns_per_op, a.ops_per_sec, b.ns_per_op, b.ops_per_sec);
    }

    // scaling table, from the runs above (no re-measurement)
    printf("\n  scaling vs 1 thread (mode0 = real code, mode1 = no MTF write):\n");
    printf("  %7s %10s %10s\n", "threads", "mode0 x", "mode1 x");
    for (int i = 0; i < n_thread_counts; i++) {
        int t = thread_counts[i];
        printf("  %7d %9.2fx %9.2fx\n", t,
               (a_ops[0] > 0) ? a_ops[i] / a_ops[0] : 0,
               (b_ops[0] > 0) ? b_ops[i] / b_ops[0] : 0);
    }
    printf("  (<1.0x means adding a thread REDUCED total throughput)\n");
    (void)a_ns; (void)b_ns;

    // ---- A2. Shared vs disjoint flows across workers ----
    // NR_Core.c hashes a packet's 5-tuple to a worker, so workers normally carry
    // DIFFERENT flows. Sharing one flow set across all workers is the worst case
    // and would overstate the problem, so measure both.
    printf("\n=== A2. Real dispatch: workers carry DISJOINT flows (flow hash) ===\n");
    printf("3 threads, mode0, N = 1024\n\n");
    printf("  %8s %18s %18s\n", "M", "shared ns/op", "disjoint ns/op");
    const int Ms3[] = { 64, 256, 512, 1024 };
    for (int i = 0; i < 4; i++) {
        int m = Ms3[i];
        seed(1024); warm_hot_flows(m);
        RESULT sh = run2(3, 0, m, 500000, 0);
        seed(1024); warm_hot_flows(m);
        RESULT dj = run2(3, 0, m, 500000, 1);
        printf("  %8d %18.1f %18.1f\n", m, sh.ns_per_op, dj.ns_per_op);
    }

    // ---- B. Scan length: N vs M ----
    printf("\n=== B. Does the scan length follow M (active flows) or N (entries)? ===\n");
    printf("3 threads, mode0. avg nodes visited per lookup:\n\n");
    printf("  %8s | %10s %10s %10s %10s\n", "N \\ M", "M=8", "M=64", "M=256", "M=1024");
    const int Ns[] = { 64, 256, 1024, 4096 };
    const int Ms[] = { 8, 64, 256, 1024 };
    for (int a = 0; a < 4; a++) {
        int n = Ns[a];
        if (n > MAX_ENTRIES) continue;
        printf("  %8d |", n);
        for (int b = 0; b < 4; b++) {
            int m = Ms[b];
            if (m > n) { printf(" %10s", "-"); continue; }
            seed(n);
            printf(" %10.1f", avg_walk(3, m, 300000));
        }
        printf("\n");
    }

    // ---- B2. Cost vs active-flow count (high-concurrency client) ----
    printf("\n=== B2. Cost vs active flows M (N = 1024 entries, all HITS) ===\n");
    printf("  %8s %16s %16s\n", "M", "1 thread ns/op", "3 threads ns/op");
    const int Ms2[] = { 8, 64, 256, 512, 1024 };
    for (int i = 0; i < 5; i++) {
        int m = Ms2[i];
        seed(1024); warm_hot_flows(m);
        RESULT r1 = run(1, 0, m, 500000);
        seed(1024); warm_hot_flows(m);
        RESULT r3 = run(3, 0, m, 500000);
        printf("  %8d %16.1f %16.1f\n", m, r1.ns_per_op, r3.ns_per_op);
    }

    // ---- C. Realistic pps budget ----
    printf("\n=== C. Budget at a realistic packet rate ===\n");
    seed(1024); warm_hot_flows(64);
    double ns1 = run(1, 0, 64, ITERS).ns_per_op;
    seed(1024); warm_hot_flows(64);
    double ns3 = run(3, 0, 64, ITERS).ns_per_op;
    printf("  per-lookup cost: 1 thread %.0f ns, 3 threads %.0f ns\n", ns1, ns3);
    const double pps[] = { 23333, 80000, 150000 };
    for (int i = 0; i < 3; i++) {
        printf("  at %7.0f pps -> %.3f%% of one core (3 threads: %.3f%%)\n",
               pps[i],
               100.0 * ns1 * pps[i] / 1e9,
               100.0 * ns3 * pps[i] / 1e9);
    }

    // ---- E. The redundant double lookup in the per-packet path ----
    printf("\n=== E. NR_Core.c case-2 walks the table TWICE per packet (same key) ===\n");
    printf("N = 1024, M = 64, all HITS\n");
    printf("mode3 = current (BOOL walk + payload walk), mode4 = proposed (one walk)\n\n");
    printf("  %8s %14s %14s %10s\n", "threads", "mode3 ns/op", "mode4 ns/op", "saved");
    const int tc2[] = { 1, 3 };
    for (int i = 0; i < 2; i++) {
        int t = tc2[i];
        seed(1024); warm_hot_flows(64);
        RESULT m3 = run(t, 3, 64, 1000000);
        seed(1024); warm_hot_flows(64);
        RESULT m4 = run(t, 4, 64, 1000000);
        printf("  %8d %14.1f %14.1f %9.0f%%\n", t, m3.ns_per_op, m4.ns_per_op,
               100.0 * (m3.ns_per_op - m4.ns_per_op) / m3.ns_per_op);
    }

    // ---- D. Miss path (new connection / stale port) ----
    printf("\n=== D. Miss path (walks the WHOLE list) ===\n");
    printf("  %8s %14s\n", "N", "1 thread ns/op");
    const int missN[] = { 64, 256, 1024, 4096 };
    for (int i = 0; i < 4; i++) {
        int n = missN[i];
        seed(n);
        // port 55555 is absent -> guaranteed full walk
        {
            LARGE_INTEGER f, t0, t1;
            QueryPerformanceFrequency(&f);
            UINT8 dst[16]; memcpy(dst, g_dst, 16);
            volatile int sink = 0;
            long it = 200000;
            QueryPerformanceCounter(&t0);
            for (long k = 0; k < it; k++)
                sink += is_connection_tracked((UINT16)55555, AF_INET, dst);
            QueryPerformanceCounter(&t1);
            printf("  %8d %14.0f\n", n,
                   ((double)(t1.QuadPart - t0.QuadPart) * 1e9) / f.QuadPart / it);
            (void)sink;
        }
    }

    clear_connections();
    DeleteCriticalSection(&lock_connections);
    WSACleanup();
    return 0;
}
