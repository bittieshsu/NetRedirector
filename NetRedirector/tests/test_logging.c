// --- TEST: engine logging helpers (log_message / log_message_throttled) ---
//
// Why this file exists: the throttled logger is the only reason an
// intermittent fault ("it worked, I restarted, now only DIRECT works until the
// uplink returns") can be diagnosed at all. If it silently dropped everything,
// or if it fired on every call, the engine log would be either empty or
// unusable exactly when it is needed - and both failure modes are invisible
// from the outside without a test.
//
// The DLL is not loaded here; NetRedirector.c is linked directly, so the file
// output path is inert (g_log_ready stays FALSE because DllMain never runs).
// What is under test is the callback contract and the throttling arithmetic,
// which are observed through g_log_callback.
#include "test_framework.h"
#include "NR_Common.h"

static int  g_cb_count = 0;
static char g_last[1024];

static void counting_callback(const char *msg)
{
    g_cb_count++;
    snprintf(g_last, sizeof(g_last), "%s", msg ? msg : "");
}

int main(void)
{
    init_locks();
    g_log_callback = counting_callback;

    printf("== log_message ==\n");
    {
        g_cb_count = 0;
        g_last[0] = '\0';
        log_message("hello %d", 42);
        CHECK(g_cb_count == 1, "log_message reaches the callback");
        CHECK(strcmp(g_last, "hello 42") == 0, "format arguments are substituted");

        g_cb_count = 0;
        log_message(NULL);
        CHECK(g_cb_count == 0, "a NULL format string is ignored");
    }

    printf("== log_message_throttled: first call passes ==\n");
    {
        g_cb_count = 0;
        g_last[0] = '\0';
        for (int i = 0; i < 5; i++)
            log_message_throttled(NR_THROTTLE_UNKNOWN_PID, 150, "burst %d", i);
        CHECK(g_cb_count == 1, "only the first call inside the window is emitted");
        CHECK(strcmp(g_last, "burst 0") == 0, "the emitted call is the first one");
    }

    printf("== log_message_throttled: collapsed count is reported ==\n");
    {
        Sleep(250);   // let the 150 ms window expire
        g_cb_count = 0;
        g_last[0] = '\0';
        log_message_throttled(NR_THROTTLE_UNKNOWN_PID, 150, "after");
        CHECK(g_cb_count == 1, "the next call after the window is emitted");
        CHECK(strstr(g_last, "after") != NULL, "the message body survives");
        CHECK(strstr(g_last, "+4 more") != NULL,
              "the 4 suppressed calls are accounted for, not silently dropped");
    }

    printf("== log_message_throttled: slots are independent ==\n");
    {
        g_cb_count = 0;
        log_message_throttled(NR_THROTTLE_NO_PROXY, 150, "other slot");
        CHECK(g_cb_count == 1,
              "a different slot is not suppressed by the first slot's window");
    }

    printf("== log_message_throttled: out-of-range slot is never throttled ==\n");
    {
        g_cb_count = 0;
        g_last[0] = '\0';
        log_message_throttled(9999, 150, "fallback %d", 7);
        log_message_throttled(9999, 150, "fallback %d", 8);
        CHECK(g_cb_count == 2, "an out-of-range slot falls back to plain logging");
        CHECK(strcmp(g_last, "fallback 8") == 0, "fallback still formats its arguments");
    }

    printf("== log_message_throttled: the UDP unknown-pid slot is separate ==\n");
    {
        // Regression guard for the UDP noise fix. The identical "could not be
        // attributed" line means two different things: for TCP it is a real
        // signal (the tracking state machine was asked about a flow it never
        // saw), while for UDP it is routine - UDP has no TIME_WAIT and no
        // handshake, so the socket is usually gone before the lookup and the
        // datagram is forwarded unchanged. If the two ever shared a slot, one
        // busy DNS client would throttle the TCP lines again, which is exactly
        // the bug the separate slot was added to fix.
        CHECK(NR_THROTTLE_UNKNOWN_PID_UDP != NR_THROTTLE_UNKNOWN_PID,
              "the UDP slot is distinct from the TCP slot");
        CHECK(NR_THROTTLE_UNKNOWN_PID_UDP < NR_THROTTLE_SLOTS,
              "the UDP slot is in range (out of range would disable throttling)");
        CHECK(NR_THROTTLE_UNKNOWN_PID_UDP_MS > 5000,
              "the UDP window is deliberately longer than the TCP one");

        // Hold the TCP slot for a minute, then use the UDP slot. The UDP call
        // must still be emitted, which is only possible if the two keep
        // separate window state.
        log_message_throttled(NR_THROTTLE_UNKNOWN_PID, 60000, "tcp window held");
        g_cb_count = 0;
        log_message_throttled(NR_THROTTLE_UNKNOWN_PID_UDP,
                              NR_THROTTLE_UNKNOWN_PID_UDP_MS, "udp window free");
        CHECK(g_cb_count == 1,
              "the TCP slot's window does not suppress the UDP slot");
    }

    return test_summary("test_logging");
}
