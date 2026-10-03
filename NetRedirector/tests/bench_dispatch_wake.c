// Microbenchmark: what does the per-packet SetEvent in dispatch_packet cost?
//
// NR_Core.c's dispatch_packet() signals the worker's wake event after EVERY
// enqueued packet, even though the worker drains the whole backlog per wakeup
// ("one wait per burst instead of one wait per packet" - see flow_worker()).
// So on a busy flow the worker is usually already awake and the SetEvent is
// redundant. SetEvent is a kernel transition (NtSetEvent), so if it is
// expensive it would be a per-packet cost that no amount of connection-table
// work can offset.
//
// Three things are measured separately, so the answer does not depend on
// subtracting one noisy number from another:
//
//   1. raw SetEvent with nobody waiting        - the worst case for redundancy
//   2. SetEvent + WaitForSingleObject round trip - the "worker was asleep" case
//   3. full producer/consumer dispatch loop, two variants:
//        A = signal on every packet   (what the code does today)
//        B = signal only on the idle->busy transition (InterlockedExchange gate)
//
// Build & run (from NetRedirector\):
//   C:\ProgramData\mingw64\mingw64\bin\gcc.exe -O2 -o tests\bench_dispatch_wake.exe ^
//       tests\bench_dispatch_wake.c -I. -lws2_32
//   tests\bench_dispatch_wake.exe

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define SLOTS       512          // == FLOW_QUEUE_SLOTS in NR_Core.c
#define PKT_BYTES   1500         // typical Ethernet MTU payload

typedef struct {
    CRITICAL_SECTION  lock;
    HANDLE            wake;
    volatile LONG     wake_pending;
    unsigned char     buf[SLOTS][PKT_BYTES];
    int               head, tail, count;
} Q;

static Q    g_q;
static long g_packets;           // total to push
static volatile LONG g_consumed;
static int  g_variant;           // 0 = SetEvent always, 1 = gated
static int  g_bursty;            // 1 = producer pauses mid-run (idle<->busy churn)
static double g_t_producer_end;  // when the producer pushed its last packet

static LARGE_INTEGER g_freq;

static double now_sec(void)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)g_freq.QuadPart;
}

// --- the two signalling styles -------------------------------------------

static void signal_always(void)
{
    SetEvent(g_q.wake);
}

static void signal_gated(void)
{
    // Only the transition 0 -> 1 signals. The worker resets the flag when it
    // finds the queue empty, so a packet arriving after that signals again.
    if (InterlockedExchange(&g_q.wake_pending, 1) == 0) SetEvent(g_q.wake);
}

// --- producer / consumer --------------------------------------------------

static DWORD WINAPI producer(LPVOID arg)
{
    unsigned char src[PKT_BYTES];
    memset(src, 0xA5, sizeof(src));
    (void)arg;

    for (long i = 0; i < g_packets; i++) {
        for (;;) {
            BOOL pushed = FALSE;
            EnterCriticalSection(&g_q.lock);
            if (g_q.count < SLOTS) {
                memcpy(g_q.buf[g_q.tail], src, PKT_BYTES);
                g_q.tail = (g_q.tail + 1) % SLOTS;
                g_q.count++;
                pushed = TRUE;
            }
            LeaveCriticalSection(&g_q.lock);
            if (pushed) break;
            Sleep(0);                 // queue full: spin for space
        }
        if (g_variant == 0) signal_always();
        else                signal_gated();

        // Bursty mode drives the idle<->busy transition hard, which is exactly
        // where a gating bug would lose a wakeup.
        if (g_bursty && (i % 2000) == 1999) Sleep(1);
    }
    g_t_producer_end = now_sec();
    return 0;
}

static DWORD WINAPI consumer(LPVOID arg)
{
    (void)arg;
    for (;;) {
        // Correct gated protocol - ORDER MATTERS:
        //   1. allow exactly one future signal
        //   2. re-check emptiness
        //   3. only then sleep
        // Resetting the flag AFTER an emptiness check loses a wakeup: a
        // producer that enqueues in that gap sees pending==1, skips SetEvent,
        // and the packet then sits until the 1 s timeout.
        if (g_variant == 1) InterlockedExchange(&g_q.wake_pending, 0);

        BOOL empty;
        EnterCriticalSection(&g_q.lock);
        empty = (g_q.count == 0);
        LeaveCriticalSection(&g_q.lock);
        if (empty) WaitForSingleObject(g_q.wake, 1000);

        for (;;) {
            int n = 0;
            EnterCriticalSection(&g_q.lock);
            n = g_q.count;
            while (g_q.count > 0) {
                g_q.head = (g_q.head + 1) % SLOTS;
                g_q.count--;
            }
            LeaveCriticalSection(&g_q.lock);
            if (n > 0) InterlockedExchangeAdd(&g_consumed, n);
            if (n == 0) break;
        }
        if (g_consumed >= g_packets) break;
    }
    return 0;
}

static double run_dispatch(int variant, long packets)
{
    HANDLE th[2];
    g_packets = packets;
    g_variant = variant;
    g_consumed = 0;
    g_q.head = g_q.tail = g_q.count = 0;
    g_q.wake_pending = 0;
    ResetEvent(g_q.wake);

    double t0 = now_sec();
    th[0] = CreateThread(NULL, 0, consumer, NULL, 0, NULL);
    th[1] = CreateThread(NULL, 0, producer, NULL, 0, NULL);
    WaitForMultipleObjects(2, th, TRUE, INFINITE);
    double t1 = now_sec();
    CloseHandle(th[0]); CloseHandle(th[1]);
    return t1 - t0;
}

// The tail latency is the lost-wakeup detector: if the gate ever drops a
// signal, the consumer blocks on the event until its 1 s timeout, so the gap
// between "producer finished" and "consumer finished" jumps to ~1000 ms.
// Normal operation is well under 1 ms. Returns the tail in milliseconds.
static double g_last_tail_ms;

static double run_dispatch_tail(int variant, long packets, int bursty)
{
    g_bursty = bursty;
    double total = run_dispatch(variant, packets);
    g_bursty = 0;
    g_last_tail_ms = (now_sec() - g_t_producer_end) * 1000.0;
    (void)total;
    return g_last_tail_ms;
}

int main(void)
{
    QueryPerformanceFrequency(&g_freq);
    InitializeCriticalSection(&g_q.lock);
    g_q.wake = CreateEvent(NULL, FALSE, FALSE, NULL);   // auto-reset, like NR_Core.c

    printf("NetRedirector flow-dispatch wake bench\n");
    printf("(mirrors dispatch_packet + flow_worker; %d-byte payload, %d slots)\n\n",
           PKT_BYTES, SLOTS);

    // ---- 1. raw SetEvent, nobody waiting ----
    {
        const int N = 2000000;
        volatile LONG sink = 0;
        LARGE_INTEGER t0, t1;
        // Leave the event signaled so every SetEvent is a "redundant" one.
        SetEvent(g_q.wake);
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            SetEvent(g_q.wake);
            sink++;
        }
        QueryPerformanceCounter(&t1);
        printf("1. raw SetEvent, no waiter           %8.1f ns/op\n",
               (double)(t1.QuadPart - t0.QuadPart) * 1e9 / g_freq.QuadPart / N);
        (void)sink;
    }

    // ---- 2. SetEvent + WaitForSingleObject round trip ----
    {
        const int N = 200000;
        LARGE_INTEGER t0, t1;
        ResetEvent(g_q.wake);
        QueryPerformanceCounter(&t0);
        for (int i = 0; i < N; i++) {
            SetEvent(g_q.wake);
            WaitForSingleObject(g_q.wake, 1000);
        }
        QueryPerformanceCounter(&t1);
        printf("2. SetEvent + Wait round trip        %8.1f ns/op\n\n",
               (double)(t1.QuadPart - t0.QuadPart) * 1e9 / g_freq.QuadPart / N);
    }

    // ---- 3. full dispatch loop, both variants ----
    const long PACKETS = 3000000;
    double a = run_dispatch(0, PACKETS);
    double b = run_dispatch(1, PACKETS);
    printf("3. producer/consumer dispatch, %ld packets\n", PACKETS);
    printf("   A. SetEvent on every packet        %8.1f ns/pkt  (%.2f M pkt/s)\n",
           a * 1e9 / PACKETS, PACKETS / a / 1e6);
    printf("   B. gated SetEvent (idle->busy)     %8.1f ns/pkt  (%.2f M pkt/s)\n",
           b * 1e9 / PACKETS, PACKETS / b / 1e6);
    printf("   saved                              %8.1f ns/pkt  (%.0f%%)\n",
           (a - b) * 1e9 / PACKETS, 100.0 * (a - b) / a);
    printf("\n   at 150k pps the difference is %.3f%% of one core.\n",
           (a - b) / PACKETS * 150000.0 * 100.0);

    // ---- 4. sanity: the gate must not lose wakeups ----
    {
        int bad = 0;
        for (int r = 0; r < 5; r++) {
            run_dispatch(1, 200000);
            if (g_consumed != 200000) bad++;
        }
        printf("\n4. gated variant, 5 x 200k runs: %s (consumed mismatch in %d runs)\n",
               bad == 0 ? "no lost wakeups" : "LOST WAKEFUPS", bad);
    }

    // ---- 5. tail latency, steady and bursty (the decisive lost-wakeup check) ----
    {
        printf("\n5. tail latency = time from 'producer pushed its last packet' to\n");
        printf("   'consumer finished'. A dropped signal shows up as ~1000 ms\n");
        printf("   (the Wait timeout); normal is sub-millisecond.\n\n");
        printf("   %-28s %12s %12s\n", "run", "tail (ms)", "verdict");
        const char *names[4] = {
            "A steady  (signal always)",
            "B steady  (gated)",
            "A bursty  (signal always)",
            "B bursty  (gated)",
        };
        int vars[4] = { 0, 1, 0, 1 };
        int burs[4] = { 0, 0, 1, 1 };
        int worst = 0;
        for (int i = 0; i < 4; i++) {
            double tail = run_dispatch_tail(vars[i], 300000, burs[i]);
            const char *v = (tail < 100.0) ? "ok" : "** LOST WAKEUP **";
            if (tail >= 100.0) worst = 1;
            printf("   %-28s %12.2f %12s\n", names[i], tail, v);
        }
        printf("\n   OVERALL: %s\n", worst ? "FAIL - a signal was dropped"
                                          : "PASS - no dropped signals in any run");
    }

    CloseHandle(g_q.wake);
    DeleteCriticalSection(&g_q.lock);
    return 0;
}
