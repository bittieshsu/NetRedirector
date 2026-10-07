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

    return test_summary("test_logging");
}
