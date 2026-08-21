// --- FILE: test_framework.h (共用測試框架, 僅供測試 EXE 使用) ---
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

// 鎖全域 (正常由 DllMain 初始化, 測試 EXE 需自行初始化)
extern CRITICAL_SECTION lock_rules;
extern CRITICAL_SECTION lock_connections;
extern CRITICAL_SECTION lock_logged;
extern CRITICAL_SECTION lock_proxies;
extern CRITICAL_SECTION lock_udp;
extern CRITICAL_SECTION lock_pid_cache;

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define CHECK(cond, msg) do { \
    g_tests_run++; \
    if (cond) { printf("  [PASS] %s\n", msg); } \
    else { g_tests_failed++; printf("  [FAIL] %s (line %d)\n", msg, __LINE__); } \
} while (0)

static void init_locks(void) {
    InitializeCriticalSection(&lock_rules);
    InitializeCriticalSection(&lock_connections);
    InitializeCriticalSection(&lock_logged);
    InitializeCriticalSection(&lock_proxies);
    InitializeCriticalSection(&lock_udp);
    InitializeCriticalSection(&lock_pid_cache);
}

static int test_summary(const char *name) {
    printf("\n==== %s: %d/%d passed ====\n", name, g_tests_run - g_tests_failed, g_tests_run);
    return g_tests_failed == 0 ? 0 : 1;
}

#endif // TEST_FRAMEWORK_H
