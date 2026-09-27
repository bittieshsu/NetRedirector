// Isolates ONE question: does a WinDivert SOCKET/FLOW-layer handle affect
// unrelated socket operations, and does that effect follow the handle or
// persist after it is closed?
//
// Why: probe_pid_map.c's safety phase found that with a SOCKET-layer RECV_ONLY
// handle open, bind() failed with WSAEACCES (10013) - the error for "refused",
// not "in use" (that is WSAEADDRINUSE, 10048). This probe separates the
// variables so the cause is measured rather than guessed:
//
//   layer x flags, and for each: not drained / drained by a thread / closed
//
// The WinDivert docs give mandatory flags per layer:
//     FLOW   : WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
//     SOCKET : WINDIVERT_FLAG_RECV_ONLY
// and describe the FLOW layer as "can be captured, but not blocked nor
// injected" while the SOCKET layer "can capture or block". So the working
// hypothesis is that a blocking-capable layer holds filtered operations until a
// verdict arrives, and RECV_ONLY forbids sending one - meaning the SOCKET layer
// is unusable for passive observation. Adding WINDIVERT_FLAG_SNIFF is tested as
// a possible way to make it observational.
//
// Build & run (from NetRedirector\; needs WinDivert.dll in cwd, so run from the
// repo root):
//   C:\ProgramData\mingw64\mingw64\bin\gcc -O2 -o tests\probe_socket_layer_safety.exe ^
//       tests\probe_socket_layer_safety.c -I. -lws2_32
//   cd .. && NetRedirector\tests\probe_socket_layer_safety.exe

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"

typedef HANDLE (WINAPI *PFN_Open)(const char *, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL   (WINAPI *PFN_Recv)(HANDLE, PVOID, UINT, UINT *, PWINDIVERT_ADDRESS);
typedef BOOL   (WINAPI *PFN_Close)(HANDLE);

static PFN_Open  pOpen;
static PFN_Recv  pRecv;
static PFN_Close pClose;

static HANDLE         g_h = INVALID_HANDLE_VALUE;
static volatile LONG  g_run = 0;
static volatile LONG  g_drained = 0;

static DWORD WINAPI drain_worker(LPVOID a)
{
    (void)a;
    unsigned char buf[512];
    WINDIVERT_ADDRESS addr;
    UINT len;
    while (InterlockedCompareExchange(&g_run, 1, 1) == 1) {
        len = 0;
        memset(&addr, 0, sizeof(addr));
        if (!pRecv(g_h, buf, sizeof(buf), &len, &addr)) {
            DWORD e = GetLastError();
            if (e == ERROR_INVALID_HANDLE || e == ERROR_OPERATION_ABORTED) break;
            continue;
        }
        InterlockedIncrement(&g_drained);
    }
    return 0;
}

// socket() + bind(ephemeral) + getsockname + close. Reports the first failure.
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
    int l = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &l);
    closesocket(s);
    return 0;
}

static void phase(const char *label, int rounds)
{
    int ok = 0;
    char first[96] = "";

    for (int i = 0; i < rounds; i++) {
        char w[96] = "";
        int e = bind_probe(w, sizeof(w));
        if (e == 0) ok++;
        else if (first[0] == 0) snprintf(first, sizeof(first), "%s", w);
    }
    printf("    %-38s %2d/%2d bound%s%s\n", label, ok, rounds,
           (ok < rounds) ? "   first: " : "", first);
}

// Full cycle for one (layer, flags) combination.
static void test_combo(const char *name, WINDIVERT_LAYER layer, UINT64 flags)
{
    printf("\n=== %s (layer %d, flags 0x%llx) ===\n", name, (int)layer,
           (unsigned long long)flags);

    phase("control: no handle", 12);

    SetLastError(0);
    g_h = pOpen("tcp or udp", layer, 0, flags);
    if (g_h == INVALID_HANDLE_VALUE) {
        printf("    WinDivertOpen FAILED err=%lu\n", GetLastError());
        return;
    }
    printf("    WinDivertOpen OK\n");

    phase("open, NOT drained", 12);

    InterlockedExchange(&g_drained, 0);
    InterlockedExchange(&g_run, 1);
    HANDLE th = CreateThread(NULL, 0, drain_worker, NULL, 0, NULL);
    Sleep(300);
    phase("open, drained by a thread", 12);
    printf("      events drained: %ld\n", (long)g_drained);

    InterlockedExchange(&g_run, 0);
    pClose(g_h);
    g_h = INVALID_HANDLE_VALUE;
    if (th) { WaitForSingleObject(th, 3000); CloseHandle(th); }
    Sleep(200);
    phase("after close", 12);
}

int main(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("FATAL: WSAStartup\n"); return 2; }

    HMODULE dll = LoadLibraryA("WinDivert.dll");
    if (!dll) { printf("FATAL: cannot load WinDivert.dll\n"); return 2; }
    pOpen  = (PFN_Open)(void *)GetProcAddress(dll, "WinDivertOpen");
    pRecv  = (PFN_Recv)(void *)GetProcAddress(dll, "WinDivertRecv");
    pClose = (PFN_Close)(void *)GetProcAddress(dll, "WinDivertClose");
    if (!pOpen || !pRecv || !pClose) { printf("FATAL: exports missing\n"); return 2; }

    printf("WinDivert layer safety probe\n");
    printf("question: does holding a handle wedge unrelated socket creation?\n");
    printf("a failure only while open, recovering after close, means the layer\n");
    printf("gates socket operations on a verdict that RECV_ONLY cannot supply.\n");

    test_combo("SOCKET layer, docs' mandatory flags",
               WINDIVERT_LAYER_SOCKET, WINDIVERT_FLAG_RECV_ONLY);

    test_combo("SOCKET layer, + SNIFF (does sniff mode make it passive?)",
               WINDIVERT_LAYER_SOCKET, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    test_combo("FLOW layer, docs' mandatory flags",
               WINDIVERT_LAYER_FLOW, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    test_combo("NETWORK layer control (relay already uses this)",
               WINDIVERT_LAYER_NETWORK, 0);

    printf("\n(For reference: WSAEACCES 10013 = refused; WSAEADDRINUSE 10048 = busy.)\n");
    WSACleanup();
    return 0;
}
