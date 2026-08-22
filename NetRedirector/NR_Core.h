// --- START OF FILE NR_Core.h ---
#ifndef NR_CORE_H
#define NR_CORE_H

#include "NR_Common.h"
#include "NR_State.h"
#include "NR_RuleEngine.h"
#include "NR_Protocol.h"
#include "NR_Utils.h"

// Thread Functions
// Packet pipeline: packet_threads[0] is the receiver (sole WinDivertRecv
// caller), [1..NUM_PACKET_THREADS-1] are flow workers fed by flow_hash().
DWORD WINAPI packet_receiver(LPVOID arg);
DWORD WINAPI flow_worker(LPVOID arg);
DWORD WINAPI local_proxy_server(LPVOID arg);
DWORD WINAPI udp_relay_server(LPVOID arg);
DWORD WINAPI cleanup_thread(LPVOID arg);
DWORD WINAPI connection_handler(LPVOID arg);
DWORD WINAPI transfer_handler(LPVOID arg);

// Flow dispatch queues (receiver -> workers). init before thread creation,
// shutdown only after the receiver and all workers have been joined.
BOOL flow_queues_init(void);
void flow_queues_shutdown(void);

// Transfer-socket registry: Stop() shuts every registered pair down so
// connection/transfer threads blocked in recv() unblock and exit. Threads
// keep ownership of closesocket() (no double-close).
BOOL register_connection_sockets(SOCKET client_socket, SOCKET proxy_socket);
void unregister_connection_sockets(SOCKET client_socket, SOCKET proxy_socket);
void shutdown_all_connections(void);

#endif // NR_CORE_H