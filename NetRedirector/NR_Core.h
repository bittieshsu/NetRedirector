// --- START OF FILE NR_Core.h ---
#ifndef NR_CORE_H
#define NR_CORE_H

#include "NR_Common.h"
#include "NR_State.h"
#include "NR_RuleEngine.h"
#include "NR_Protocol.h"
#include "NR_Utils.h"

// Thread Functions
DWORD WINAPI packet_processor(LPVOID arg);
DWORD WINAPI local_proxy_server(LPVOID arg);
DWORD WINAPI udp_relay_server(LPVOID arg);
DWORD WINAPI cleanup_thread(LPVOID arg);
DWORD WINAPI connection_handler(LPVOID arg);
DWORD WINAPI transfer_handler(LPVOID arg);

#endif // NR_CORE_H