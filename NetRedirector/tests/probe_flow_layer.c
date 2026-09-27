// Probe: does this WinDivert build actually support the FLOW / SOCKET layers,
// and do they deliver the (local_addr, local_port) -> ProcessId mapping the
// relay needs?
//
// Why: NR_Utils.c resolves a packet's owning process by calling
// GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL), which the sibling benchmark
// (bench_conn_lookup.c) measures at ~650 us per call - a FIXED cost, not a
// per-row one. That call happens for every new connection. The FLOW layer
// would deliver the same pid asynchronously, for free.
//
// [Corrected] A first version of this probe passed flags = 0 and concluded
// "layer NOT supported" from ERROR_INVALID_PARAMETER (87). That was wrong.
// WinDivertOpen validates layer, priority AND flags together, and the docs give
// each layer mandatory flags:
//     FLOW   : WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
//     SOCKET : WINDIVERT_FLAG_RECV_ONLY
//     REFLECT: WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
// So the probe now passes the documented flags, and still reports the raw
// error for each combination rather than interpreting it for the reader.
//
// Build & run (from NetRedirector\):
//   C:\ProgramData\mingw64\mingw64\bin\gcc -O2 -o tests\probe_flow_layer.exe ^
//       tests\probe_flow_layer.c -I. -lws2_32
//   cd .. && NetRedirector\tests\probe_flow_layer.exe

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"

typedef HANDLE (WINAPI *PFN_Open)(const char *, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL   (WINAPI *PFN_Recv)(HANDLE, PVOID, UINT, UINT *, PWINDIVERT_ADDRESS);
typedef BOOL   (WINAPI *PFN_Close)(HANDLE);
typedef BOOL   (WINAPI *PFN_SetParam)(HANDLE, WINDIVERT_PARAM, UINT64);

static const char *err_name(DWORD e)
{
    switch (e) {
    case ERROR_ACCESS_DENIED:          return "ERROR_ACCESS_DENIED (needs admin)";
    case ERROR_INVALID_PARAMETER:      return "ERROR_INVALID_PARAMETER (bad filter/layer/priority/flags)";
    case ERROR_FILE_NOT_FOUND:         return "ERROR_FILE_NOT_FOUND (driver not installed)";
    case ERROR_SERVICE_DOES_NOT_EXIST: return "ERROR_SERVICE_DOES_NOT_EXIST (driver not installed)";
    default:                           return "(see code)";
    }
}

static void try_layer(const char *label, WINDIVERT_LAYER layer, UINT64 flags,
                      PFN_Open pOpen, PFN_Recv pRecv, PFN_Close pClose,
                      PFN_SetParam pSetParam)
{
    printf("--- %s (layer %d, flags 0x%llx) ---\n", label, (int)layer,
           (unsigned long long)flags);
    SetLastError(0);
    HANDLE h = pOpen("tcp or udp", layer, 0, flags);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        printf("  WinDivertOpen FAILED  err=%lu  %s\n\n", e, err_name(e));
        return;
    }
    printf("  WinDivertOpen OK  handle=%p\n", (void *)h);

    if (pSetParam) pSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 2000);

    WINDIVERT_ADDRESS addr;
    unsigned char buf[4096];
    UINT len = 0;
    int got = 0;
    DWORD t0 = GetTickCount();

    // Collect events for ~2 s. FLOW/SOCKET events fire on their own; if the
    // machine is idle we may legitimately see none, which is not a failure.
    while (GetTickCount() - t0 < 2000 && got < 8) {
        memset(&addr, 0, sizeof(addr));
        len = 0;
        if (!pRecv(h, buf, sizeof(buf), &len, &addr)) {
            DWORD e = GetLastError();
            if (e == 995 || e == ERROR_INVALID_HANDLE) break;   // aborted on close
            continue;
        }
        got++;
        if (layer == WINDIVERT_LAYER_FLOW) {
            PWINDIVERT_DATA_FLOW f = &addr.Flow;
            // Raw dump on purpose: the byte order / slot holding the IPv4
            // address inside LocalAddr[4] is NOT something to assume. Print the
            // four words as-is so the layout is read off the data, not guessed.
            printf("  event=%u pid=%lu proto=%u ports=%u->%u "
                   "L=[%08lx %08lx %08lx %08lx] R=[%08lx %08lx %08lx %08lx] ep=%llu\n",
                   (unsigned)addr.Event, (unsigned long)f->ProcessId, (unsigned)f->Protocol,
                   (unsigned)f->LocalPort, (unsigned)f->RemotePort,
                   (unsigned long)f->LocalAddr[0], (unsigned long)f->LocalAddr[1],
                   (unsigned long)f->LocalAddr[2], (unsigned long)f->LocalAddr[3],
                   (unsigned long)f->RemoteAddr[0], (unsigned long)f->RemoteAddr[1],
                   (unsigned long)f->RemoteAddr[2], (unsigned long)f->RemoteAddr[3],
                   (unsigned long long)f->EndpointId);
        } else if (layer == WINDIVERT_LAYER_SOCKET) {
            PWINDIVERT_DATA_SOCKET s = &addr.Socket;
            printf("  event=%u pid=%lu proto=%u localport=%u remoteport=%u "
                   "L=[%08lx %08lx %08lx %08lx] R=[%08lx %08lx %08lx %08lx]\n",
                   (unsigned)addr.Event, (unsigned long)s->ProcessId,
                   (unsigned)s->Protocol, (unsigned)s->LocalPort, (unsigned)s->RemotePort,
                   (unsigned long)s->LocalAddr[0], (unsigned long)s->LocalAddr[1],
                   (unsigned long)s->LocalAddr[2], (unsigned long)s->LocalAddr[3],
                   (unsigned long)s->RemoteAddr[0], (unsigned long)s->RemoteAddr[1],
                   (unsigned long)s->RemoteAddr[2], (unsigned long)s->RemoteAddr[3]);
        } else {
            printf("  event=%u outbound=%u len=%u\n",
                   (unsigned)addr.Event, (unsigned)addr.Outbound, len);
        }
    }
    printf("  events received in 2 s: %d%s\n\n", got,
           got == 0 ? "  (idle machine - layer still works)" : "");
    pClose(h);
}

int main(void)
{
    HMODULE dll = LoadLibraryA("WinDivert.dll");
    if (!dll) { printf("FATAL: cannot load WinDivert.dll (err=%lu)\n", GetLastError()); return 2; }

    PFN_Open     pOpen     = (PFN_Open)(void *)GetProcAddress(dll, "WinDivertOpen");
    PFN_Recv     pRecv     = (PFN_Recv)(void *)GetProcAddress(dll, "WinDivertRecv");
    PFN_Close    pClose    = (PFN_Close)(void *)GetProcAddress(dll, "WinDivertClose");
    PFN_SetParam pSetParam = (PFN_SetParam)(void *)GetProcAddress(dll, "WinDivertSetParam");
    if (!pOpen || !pRecv || !pClose) { printf("FATAL: exports missing\n"); return 2; }

    printf("WinDivert layer support probe\n");
    printf("(an idle machine may deliver zero events; that is not a failure)\n\n");

    // Control first: the layer the relay already uses. If this one fails, the
    // environment (not the layer) is the problem.
    try_layer("NETWORK layer (control)", WINDIVERT_LAYER_NETWORK, 0,
              pOpen, pRecv, pClose, pSetParam);

    // Documented mandatory flags for each layer.
    try_layer("FLOW layer",   WINDIVERT_LAYER_FLOW,
              WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY,
              pOpen, pRecv, pClose, pSetParam);
    try_layer("SOCKET layer", WINDIVERT_LAYER_SOCKET,
              WINDIVERT_FLAG_RECV_ONLY,
              pOpen, pRecv, pClose, pSetParam);

    return 0;
}

