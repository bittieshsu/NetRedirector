// --- START OF FILE NR_Common.h ---
#ifndef NR_COMMON_H
#define NR_COMMON_H

// Prevent windows.h from including the old winsock.h, resolving macro redefinition errors
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mstcpip.h>  // Include tcp_keepalive definition
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

// Include original header to get Enum definitions (ProxyType, RuleAction, RuleProtocol)
#include "NetRedirector.h" 

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// === Constants ===
#define MAXBUF 0xFFFF
#define LOCAL_PROXY_PORT 33100
#define LOCAL_UDP_RELAY_PORT 33200
#define MAX_PROCESS_NAME 256
#define TRANSFER_BUF_SIZE 65536
#define NUM_PACKET_THREADS 4
#define RULE_ACTION_PENDING 3
#define TCP_TIMEOUT_MS 3600000   // 1 hour
#define UDP_TIMEOUT_MS 600000    // 10 minutes

// Max text length of an IP address (IPv6: 45 chars + null)
#define MAX_IP_STR 48

// === Struct Definitions ===

// Proxy Config structure definition
typedef struct PROXY_CONFIG {
    UINT32 proxy_id;
    char name[256];           // Proxy name
    char proxy_ip[64];        // Proxy IP
    UINT16 proxy_port;        // Proxy port
    ProxyType proxy_type;     // Proxy type
    char username[256];       // Username
    char password[256];       // Password
    BOOL enabled;             // Is enabled
    struct PROXY_CONFIG *next;
} PROXY_CONFIG;

// Process Rule Structure
typedef struct PROCESS_RULE {
    UINT32 rule_id;
    char process_name[MAX_PROCESS_NAME];
    DWORD target_pid;     // New field: if 0 ignore, if non-zero match PID
    char *target_hosts;   // Dynamic: IP filter
    char *target_ports;   // Dynamic: Port filter
    RuleProtocol protocol;
    RuleAction action;
    UINT32 proxy_id;
    BOOL enabled;
    struct PROCESS_RULE *next;
} PROCESS_RULE;

// Connection Tracking Structure
// Addresses are stored in network byte order: IPv4 uses the first 4 bytes,
// IPv6 uses all 16 bytes. family indicates which interpretation is valid.
typedef struct CONNECTION_INFO {
    UINT16 src_port;
    int family;               // AF_INET or AF_INET6
    UINT8 src_addr[16];
    UINT8 orig_dest_addr[16];
    UINT16 orig_dest_port;
    UINT32 proxy_id;
    RuleAction action;
    DWORD last_activity;
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

// UDP Relay Association
typedef struct UDP_ASSOCIATION {
    UINT32 proxy_id;
    SOCKET control_socket;
    SOCKET udp_socket;
    struct sockaddr_in relay_addr;
    DWORD last_activity;
    struct UDP_ASSOCIATION *next;
} UDP_ASSOCIATION;

// Connection Config for Threads
typedef struct {
    SOCKET client_socket;
    int family;               // AF_INET or AF_INET6 (of the local app connection)
    UINT16 orig_dest_port;
    UINT32 proxy_id;
} CONNECTION_CONFIG;

// Data Transfer Config
typedef struct {
    SOCKET from_socket;
    SOCKET to_socket;
} TRANSFER_CONFIG;

// Logged Connection for Deduplication
typedef struct LOGGED_CONNECTION {
    DWORD pid;
    int family;               // AF_INET or AF_INET6
    UINT8 dest_addr[16];
    UINT16 dest_port;
    RuleAction action;
    struct LOGGED_CONNECTION *next;
} LOGGED_CONNECTION;

// === Shared Global Variables (Extern) ===

extern CRITICAL_SECTION lock_cs;
extern BOOL running;
extern DWORD g_current_process_id;

// Global Configuration
extern char g_proxy_ip[64];
extern UINT16 g_proxy_port;
extern UINT16 g_local_relay_port;
extern ProxyType g_proxy_type;
extern char g_proxy_username[256];
extern char g_proxy_password[256];
extern PROXY_CONFIG *proxy_configs;
extern UINT32 g_next_proxy_id;
extern UINT32 g_next_rule_id;
extern BOOL g_dns_via_proxy;
extern RuleAction g_unknown_process_action;

// Callbacks
extern LogCallback g_log_callback;
extern ConnectionCallback g_connection_callback;

// Handles
extern HANDLE windivert_handle;
extern HANDLE packet_threads[NUM_PACKET_THREADS];
extern HANDLE proxy_thread;
extern HANDLE udp_relay_thread;
extern SOCKET udp_relay_socket;
extern SOCKET udp_relay_socket6;

// Shared Helper Function for Logging
void log_message(const char *msg, ...);

#endif // NR_COMMON_H