// --- FILE: NR_Utils.c ---
#include "NR_Utils.h"
#include <ws2tcpip.h> // [Added] for getaddrinfo

// === PID Lookup Caches ===
//
// get_process_id_from_*() call GetExtendedTcpTable / GetExtendedUdpTable, which
// enumerate the ENTIRE system connection table. On an active machine that is a
// sizeable kernel+user-space cost when it happens for every new connection.
//
// Two complementary caches reduce the cost:
//   1. PID_RESULT_CACHE  : (family, local ip, local port, is_udp) -> pid
//      UDP sockets are long-lived and reused for many destinations, so a single
//      socket only needs ONE table scan per TTL window instead of one per
//      packet/flow. TCP port reuse (TIME_WAIT recycling, SYN retransmits) also
//      benefits. A cache MISS always falls through to a fresh table scan, so a
//      brand-new connection can never be "lost" to a stale snapshot.
//   2. PROCESS_NAME_CACHE: pid -> full process path. Eliminates the
//      OpenProcess + QueryFullProcessImageNameA syscall pair for subsequent
//      connections opened by the same process (browsers/games open hundreds).
//
// Both are guarded by lock_cs. They are only touched on the "new connection"
// path (not per steady-state packet), so lock contention is negligible.
// Entries expire via TTL (GetTickCount, wraps safely with unsigned math) and
// are fully cleared by clear_pid_cache() on NetRedirector_Stop.

#define PID_RESULT_CACHE_SIZE 128
#define PID_RESULT_CACHE_TTL_TCP_MS 1500
#define PID_RESULT_CACHE_TTL_UDP_MS 5000

typedef struct {
    DWORD timestamp;
    int family;               // AF_INET or AF_INET6
    BOOL is_udp;
    UINT8 local_addr[16];     // network byte order (IPv4 uses first 4 bytes)
    UINT16 local_port;        // host byte order
    DWORD pid;
} PID_RESULT_CACHE_ENTRY;

static PID_RESULT_CACHE_ENTRY g_pid_result_cache[PID_RESULT_CACHE_SIZE];
static UINT32 g_pid_cache_next_slot = 0;   // round-robin replacement

#define PROCESS_NAME_CACHE_SIZE 64
#define PROCESS_NAME_CACHE_TTL_MS 5000

typedef struct {
    DWORD pid;
    DWORD timestamp;
    char name[MAX_PROCESS_NAME];
} PROCESS_NAME_CACHE_ENTRY;

static PROCESS_NAME_CACHE_ENTRY g_process_name_cache[PROCESS_NAME_CACHE_SIZE];

// Look up a cached pid result. Returns 0 on miss/expired.
static DWORD pid_result_cache_lookup(int family, BOOL is_udp, const UINT8 *local_addr, UINT16 local_port)
{
    DWORD now = GetTickCount();
    DWORD ttl = is_udp ? PID_RESULT_CACHE_TTL_UDP_MS : PID_RESULT_CACHE_TTL_TCP_MS;
    int addr_len = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_cs);
    for (UINT32 i = 0; i < PID_RESULT_CACHE_SIZE; i++) {
        PID_RESULT_CACHE_ENTRY *e = &g_pid_result_cache[i];
        if (e->pid == 0) continue;
        if (e->family != family || e->is_udp != is_udp || e->local_port != local_port) continue;
        if ((now - e->timestamp) > ttl) continue;
        if (memcmp(e->local_addr, local_addr, addr_len) != 0) continue;
        LeaveCriticalSection(&lock_cs);
        return e->pid;
    }
    LeaveCriticalSection(&lock_cs);
    return 0;
}

// Store a pid result. Refreshes an existing entry for the same socket, else
// replaces the next round-robin slot. Failures (pid == 0) are NOT cached so a
// transient miss always retries a real table scan.
static void pid_result_cache_store(int family, BOOL is_udp, const UINT8 *local_addr, UINT16 local_port, DWORD pid)
{
    if (pid == 0) return;
    int addr_len = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_cs);
    for (UINT32 i = 0; i < PID_RESULT_CACHE_SIZE; i++) {
        PID_RESULT_CACHE_ENTRY *e = &g_pid_result_cache[i];
        if (e->pid == 0) continue;
        if (e->family == family && e->is_udp == is_udp && e->local_port == local_port &&
            memcmp(e->local_addr, local_addr, addr_len) == 0) {
            e->timestamp = GetTickCount();
            e->pid = pid;
            LeaveCriticalSection(&lock_cs);
            return;
        }
    }
    PID_RESULT_CACHE_ENTRY *slot = &g_pid_result_cache[g_pid_cache_next_slot++ % PID_RESULT_CACHE_SIZE];
    slot->timestamp = GetTickCount();
    slot->family = family;
    slot->is_udp = is_udp;
    memset(slot->local_addr, 0, sizeof(slot->local_addr));
    memcpy(slot->local_addr, local_addr, addr_len);
    slot->local_port = local_port;
    slot->pid = pid;
    LeaveCriticalSection(&lock_cs);
}

void clear_pid_cache(void)
{
    EnterCriticalSection(&lock_cs);
    memset(g_pid_result_cache, 0, sizeof(g_pid_result_cache));
    memset(g_process_name_cache, 0, sizeof(g_process_name_cache));
    g_pid_cache_next_slot = 0;
    LeaveCriticalSection(&lock_cs);
}

// [Preserved] Original parse_ipv4 (as auxiliary for resolve_hostname)
UINT32 parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}

// [Added] From : Support for domain name resolution
UINT32 resolve_hostname(const char *hostname)
{
    if (hostname == NULL || hostname[0] == '\0')
        return 0;

    // 1. First try to parse as pure IP
    UINT32 ip = parse_ipv4(hostname);
    if (ip != 0) return ip;

    // 2. If not IP, try DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // Only take IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        log_message("Failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET) {
        if (result != NULL) freeaddrinfo(result);
        log_message("No IPv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    UINT32 resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);

    // log_message("Resolved %s to %u.%u.%u.%u", hostname, ...); // Optional: Enable logging
    return resolved_ip;
}

// [Preserved] Helper function
const char* extract_filename(const char* path)
{
    if (!path) return "";
    const char* last_backslash = strrchr(path, '\\');
    const char* last_slash = strrchr(path, '/');
    const char* last_separator = (last_backslash > last_slash) ? last_backslash : last_slash;
    return last_separator ? (last_separator + 1) : path;
}

// [Preserved] KeepAlive and Base64
void EnableKeepAlive(SOCKET s) {
    if (s == INVALID_SOCKET) return;
    BOOL bKeepAlive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&bKeepAlive, sizeof(bKeepAlive));
    struct tcp_keepalive alive_in = { 0 };
    alive_in.onoff = 1;
    alive_in.keepalivetime = 20000;
    alive_in.keepaliveinterval = 3000;
    DWORD dwBytesRet = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), NULL, 0, &dwBytesRet, NULL, NULL);
}

void base64_encode(const char* input, char* output, size_t output_size) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_len = strlen(input);
    size_t output_len = 0;
    for (size_t i = 0; i < input_len && output_len < output_size - 4; i += 3) {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;
        output[output_len++] = base64_chars[b1 >> 2];
        output[output_len++] = base64_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}

// [Preserved] Process ID retrieval logic — now cache-first (see caches above)
DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port) {
    UINT8 addr4[4];
    memcpy(addr4, &src_ip, 4);
    DWORD cached = pid_result_cache_lookup(AF_INET, FALSE, addr4, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_TCPTABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    tcp_table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!tcp_table) return 0;
    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *row = &tcp_table->table[i];
            if (row->dwLocalAddr == src_ip && ntohs((UINT16)row->dwLocalPort) == src_port) {
                pid = row->dwOwningPid; break;
            }
        }
    }
    free(tcp_table);
    pid_result_cache_store(AF_INET, FALSE, addr4, src_port, pid);
    return pid;
}

DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port) {
    UINT8 addr4[4];
    memcpy(addr4, &src_ip, 4);
    DWORD cached = pid_result_cache_lookup(AF_INET, TRUE, addr4, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_UDPTABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    udp_table = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!udp_table) return 0;
    if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];
            if (row->dwLocalAddr == src_ip && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
        }
        if (pid == 0) { // Try 0.0.0.0 match
            for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
                MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];
                if (row->dwLocalAddr == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
            }
        }
    }
    free(udp_table);
    pid_result_cache_store(AF_INET, TRUE, addr4, src_port, pid);
    return pid;
}

// === IPv6 Process ID lookup ===
DWORD get_process_id_from_connection6(const UINT8 *src_ip6, UINT16 src_port) {
    DWORD cached = pid_result_cache_lookup(AF_INET6, FALSE, src_ip6, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_TCP6TABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    tcp_table = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
    if (!tcp_table) return 0;
    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            MIB_TCP6ROW_OWNER_PID *row = &tcp_table->table[i];
            if (memcmp(row->ucLocalAddr, src_ip6, 16) == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) {
                pid = row->dwOwningPid; break;
            }
        }
    }
    free(tcp_table);
    pid_result_cache_store(AF_INET6, FALSE, src_ip6, src_port, pid);
    return pid;
}

DWORD get_process_id_from_udp_connection6(const UINT8 *src_ip6, UINT16 src_port) {
    DWORD cached = pid_result_cache_lookup(AF_INET6, TRUE, src_ip6, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_UDP6TABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    udp_table = (MIB_UDP6TABLE_OWNER_PID *)malloc(size);
    if (!udp_table) return 0;
    if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
            MIB_UDP6ROW_OWNER_PID *row = &udp_table->table[i];
            if (memcmp(row->ucLocalAddr, src_ip6, 16) == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
        }
        if (pid == 0) { // Try :: (unspecified) match
            const UINT8 zero6[16] = {0};
            for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
                MIB_UDP6ROW_OWNER_PID *row = &udp_table->table[i];
                if (memcmp(row->ucLocalAddr, zero6, 16) == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
            }
        }
    }
    free(udp_table);
    pid_result_cache_store(AF_INET6, TRUE, src_ip6, src_port, pid);
    return pid;
}

// === IPv6 helpers ===

void addr_to_string(int family, const UINT8 *addr, char *buf, size_t size)
{
    if (buf == NULL || size == 0) return;
    if (family == AF_INET6) {
        if (inet_ntop(AF_INET6, addr, buf, (DWORD)size) == NULL)
            snprintf(buf, size, "::");
    } else {
        snprintf(buf, size, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
}

// Multicast (ff00::/8), link-local (fe80::/10), loopback (::1), unspecified (::)
BOOL is_multicast_or_special6(const UINT8 *a)
{
    if (a[0] == 0xFF) return TRUE;
    if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return TRUE;
    for (int i = 1; i < 16; i++) if (a[i] != 0) return FALSE;
    return (a[0] == 0x00 || a[0] == 0x01);
}

// --- LAN / On-link Detection ---
// Caches the local interface addresses (IPv4 + IPv6) and their prefix lengths.
// Used to auto-direct traffic that stays within the local network, so that
// LAN file transfers never get routed through an external proxy (e.g. a
// phone's SOCKS5 server going out over a 5G connection and back).

#define MAX_LOCAL_ADDRS 64

typedef struct LOCAL_ADDR {
    int family;              // AF_INET or AF_INET6
    UINT8 addr[16];          // Network byte order
    UINT8 prefix_len;
} LOCAL_ADDR;

static LOCAL_ADDR g_local_addrs[MAX_LOCAL_ADDRS];
static int g_local_addr_count = 0;

void refresh_local_addresses(void)
{
    ULONG size = 0;
    DWORD ret;
    PIP_ADAPTER_ADDRESSES adapters = NULL, cur;
    PIP_ADAPTER_UNICAST_ADDRESS unicast;

    g_local_addr_count = 0;

    // First call returns ERROR_BUFFER_OVERFLOW with the required size
    ret = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, NULL, &size);
    if (ret != ERROR_BUFFER_OVERFLOW || size == 0) return;

    adapters = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if (adapters == NULL) return;

    ret = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, adapters, &size);
    if (ret != NO_ERROR) { free(adapters); return; }

    for (cur = adapters; cur != NULL && g_local_addr_count < MAX_LOCAL_ADDRS; cur = cur->Next) {
        if (cur->OperStatus != IfOperStatusUp) continue;
        if (cur->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (unicast = cur->FirstUnicastAddress; unicast != NULL; unicast = unicast->Next) {
            int family = unicast->Address.lpSockaddr->sa_family;
            UINT8 prefix = unicast->OnLinkPrefixLength;
            LOCAL_ADDR *slot = &g_local_addrs[g_local_addr_count];

            // Only trust realistic LAN prefixes; a /0 or /32-ish entry would
            // otherwise make everything (or nothing) look on-link.
            if (family == AF_INET) {
                if (prefix < 8 || prefix > 30) continue;
                struct sockaddr_in *sa = (struct sockaddr_in *)unicast->Address.lpSockaddr;
                slot->family = AF_INET;
                slot->prefix_len = prefix;
                memcpy(slot->addr, &sa->sin_addr, 4);
                g_local_addr_count++;
            } else if (family == AF_INET6) {
                if (prefix < 8 || prefix > 126) continue;
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
                slot->family = AF_INET6;
                slot->prefix_len = prefix;
                memcpy(slot->addr, &sa6->sin6_addr, 16);
                g_local_addr_count++;
            }
            if (g_local_addr_count >= MAX_LOCAL_ADDRS) break;
        }
    }
    free(adapters);
}

static void prefix_to_mask(UINT8 prefix, UINT8 *mask, int len)
{
    int full = prefix / 8;
    int rem = prefix % 8;
    memset(mask, 0, len);
    for (int i = 0; i < full && i < len; i++) mask[i] = 0xFF;
    if (full < len && rem > 0) mask[full] = (UINT8)(0xFF << (8 - rem));
}

BOOL is_lan_or_on_link_address(int family, const UINT8 *addr)
{
    if (addr == NULL) return FALSE;

    if (family == AF_INET) {
        // Private ranges (RFC 1918): 10/8, 172.16/12, 192.168/16
        if (addr[0] == 10) return TRUE;
        if (addr[0] == 172 && (addr[1] & 0xF0) == 16) return TRUE;
        if (addr[0] == 192 && addr[1] == 168) return TRUE;
    } else if (family == AF_INET6) {
        // Unique Local Address (RFC 4193): fc00::/7
        if ((addr[0] & 0xFE) == 0xFC) return TRUE;
    } else {
        return FALSE;
    }

    // On-link check: destination belongs to the same subnet as one of our
    // local addresses (covers global-scope IPv6 like 2001:b011:...:xxxx).
    for (int i = 0; i < g_local_addr_count; i++) {
        LOCAL_ADDR *local = &g_local_addrs[i];
        if (local->family != family) continue;

        UINT8 mask[16];
        prefix_to_mask(local->prefix_len, mask, (family == AF_INET) ? 4 : 16);
        int len = (family == AF_INET) ? 4 : 16;
        BOOL same = TRUE;
        for (int b = 0; b < len; b++) {
            if ((addr[b] & mask[b]) != (local->addr[b] & mask[b])) { same = FALSE; break; }
        }
        if (same) return TRUE;
    }
    return FALSE;
}

BOOL match_ip_pattern6(const char *pattern, const UINT8 *ip)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0) return TRUE;
    char addr_str[MAX_IP_STR];
    addr_to_string(AF_INET6, ip, addr_str, sizeof(addr_str));
    return _stricmp(pattern, addr_str) == 0;
}

BOOL match_ip_list6(const char *ip_list, const UINT8 *ip)
{
    if (!ip_list || !ip_list[0] || !strcmp(ip_list, "*")) return TRUE;
    size_t len = strlen(ip_list)+1; char *copy = malloc(len); if(!copy) return FALSE;
    strncpy(copy, ip_list, len); BOOL matched = FALSE;
    char *token = strtok(copy, ";");
    while(token) {
        while(*token==' '||*token=='\t') token++;
        if(match_ip_pattern6(token, ip)) { matched = TRUE; break; }
        token = strtok(NULL, ";");
    }
    free(copy); return matched;
}

BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size) {
    if (pid == 0 || name == NULL || name_size == 0) return FALSE;
    if (pid == 4) { strncpy(name, "System", name_size - 1); name[name_size - 1] = '\0'; return TRUE; } // Small improvement in : System process

    DWORD now = GetTickCount();

    // 1. Cache lookup (avoids OpenProcess + QueryFullProcessImageNameA per new connection)
    EnterCriticalSection(&lock_cs);
    for (int i = 0; i < PROCESS_NAME_CACHE_SIZE; i++) {
        PROCESS_NAME_CACHE_ENTRY *e = &g_process_name_cache[i];
        if (e->pid == pid && e->name[0] && (now - e->timestamp) <= PROCESS_NAME_CACHE_TTL_MS) {
            strncpy(name, e->name, name_size - 1);
            name[name_size - 1] = '\0';
            LeaveCriticalSection(&lock_cs);
            return TRUE;
        }
    }
    LeaveCriticalSection(&lock_cs);

    // 2. Miss: query the system
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    char full_path[MAX_PATH];
    DWORD path_len = MAX_PATH;
    BOOL ok = FALSE;
    if (QueryFullProcessImageNameA(hProcess, 0, full_path, &path_len)) {
        strncpy(name, full_path, name_size - 1);
        name[name_size - 1] = '\0';
        ok = TRUE;

        // 3. Store into cache: refresh the slot for this pid, else reuse the
        //    oldest/empty slot (simple LRU-ish replacement).
        EnterCriticalSection(&lock_cs);
        int slot = -1;
        int oldest_slot = 0;
        DWORD oldest_ts = 0xFFFFFFFF;
        for (int i = 0; i < PROCESS_NAME_CACHE_SIZE; i++) {
            PROCESS_NAME_CACHE_ENTRY *e = &g_process_name_cache[i];
            if (e->pid == pid) { slot = i; break; }
            if (!e->name[0]) { slot = i; break; }
            if (e->timestamp < oldest_ts) { oldest_ts = e->timestamp; oldest_slot = i; }
        }
        if (slot < 0) slot = oldest_slot;
        PROCESS_NAME_CACHE_ENTRY *e = &g_process_name_cache[slot];
        e->pid = pid;
        e->timestamp = now;
        strncpy(e->name, full_path, MAX_PROCESS_NAME - 1);
        e->name[MAX_PROCESS_NAME - 1] = '\0';
        LeaveCriticalSection(&lock_cs);
    }
    CloseHandle(hProcess);
    return ok;
}

// [Preserved] IP/Port Pattern matching logic
BOOL match_ip_pattern(const char *pattern, UINT32 ip) {
    if (pattern == NULL || strcmp(pattern, "*") == 0) return TRUE;
    unsigned char ip_octets[4];
    ip_octets[0] = (ip >> 0) & 0xFF; ip_octets[1] = (ip >> 8) & 0xFF;
    ip_octets[2] = (ip >> 16) & 0xFF; ip_octets[3] = (ip >> 24) & 0xFF;
    char pattern_copy[256]; strncpy(pattern_copy, pattern, sizeof(pattern_copy)-1); pattern_copy[255]='\0';
    char pattern_octets[4][16]; int octet_count=0, char_idx=0;
    for(int i=0; i<=(int)strlen(pattern_copy) && octet_count<4; i++) {
        if(pattern_copy[i]=='.'||pattern_copy[i]=='\0') {
            pattern_octets[octet_count][char_idx]='\0'; octet_count++; char_idx=0;
            if(pattern_copy[i]=='\0') break;
        } else if(char_idx<15) pattern_octets[octet_count][char_idx++] = pattern_copy[i];
    }
    if(octet_count!=4) return FALSE;
    for(int i=0; i<4; i++) {
        if(strcmp(pattern_octets[i], "*")==0) continue;
        if(atoi(pattern_octets[i]) != ip_octets[i]) return FALSE;
    }
    return TRUE;
}

BOOL match_port_pattern(const char *pattern, UINT16 port) {
    if (pattern == NULL || strcmp(pattern, "*") == 0) return TRUE;
    char *dash = strchr(pattern, '-');
    if (dash != NULL) {
        int start = atoi(pattern); int end = atoi(dash + 1);
        return (port >= start && port <= end);
    }
    return (port == atoi(pattern));
}

BOOL match_ip_list(const char *ip_list, UINT32 ip) {
    if (!ip_list || !ip_list[0] || !strcmp(ip_list, "*")) return TRUE;
    size_t len = strlen(ip_list)+1; char *copy = malloc(len); if(!copy) return FALSE;
    strncpy(copy, ip_list, len); BOOL matched = FALSE;
    char *token = strtok(copy, ";");
    while(token) {
        while(*token==' '||*token=='\t') token++;
        if(match_ip_pattern(token, ip)) { matched = TRUE; break; }
        token = strtok(NULL, ";");
    }
    free(copy); return matched;
}

BOOL match_port_list(const char *port_list, UINT16 port) {
    if (!port_list || !port_list[0] || !strcmp(port_list, "*")) return TRUE;
    size_t len = strlen(port_list)+1; char *copy = malloc(len); if(!copy) return FALSE;
    strncpy(copy, port_list, len); BOOL matched = FALSE;
    char *token = strtok(copy, ",;");
    while(token) {
        while(*token==' '||*token=='\t') token++;
        if(match_port_pattern(token, port)) { matched = TRUE; break; }
        token = strtok(NULL, ",;");
    }
    free(copy); return matched;
}

// [Modified] Use  improved matching logic (Wildcard & Full Path Fixes)
BOOL match_process_pattern(const char *pattern, const char *process_full_path)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0) return TRUE;

    // Windows path processing: Extract filename
    const char *filename = strrchr(process_full_path, '\\');
    if (filename != NULL) filename++;
    else filename = process_full_path;

    size_t pattern_len = strlen(pattern);
    size_t name_len = strlen(filename);
    size_t full_path_len = strlen(process_full_path);

    // Determine if Pattern contains path separators (if yes, match full path; otherwise match filename only)
    BOOL is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);
    const char *match_target = is_full_path_pattern ? process_full_path : filename;
    size_t target_len = is_full_path_pattern ? full_path_len : name_len;

    // 1. "fire*" suffix wildcard
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*') {
        return _strnicmp(pattern, match_target, pattern_len - 1) == 0;
    }

    // 2. "*.exe" prefix wildcard
    if (pattern_len > 1 && pattern[0] == '*') {
        const char *pattern_suffix = pattern + 1;
        size_t suffix_len = pattern_len - 1;
        if (target_len >= suffix_len) {
            return _stricmp(match_target + target_len - suffix_len, pattern_suffix) == 0;
        }
        return FALSE;
    }

    // 3. "fire*.exe" middle wildcard
    const char *star = strchr(pattern, '*');
    if (star != NULL) {
        size_t prefix_len = star - pattern;
        const char *suffix = star + 1;
        size_t suffix_len = strlen(suffix);

        if (_strnicmp(pattern, match_target, prefix_len) != 0) return FALSE;
        if (target_len < prefix_len + suffix_len) return FALSE;
        return _stricmp(match_target + target_len - suffix_len, suffix) == 0;
    }

    // 4. Exact match (Case Insensitive)
    return _stricmp(pattern, match_target) == 0;
}

// [Modified] Use List matching logic (more robust handling of quotes and whitespace)
BOOL match_process_list(const char *process_list, const char *process_name)
{
    if (process_list == NULL || process_list[0] == '\0' || strcmp(process_list, "*") == 0) return TRUE;
    size_t len = strlen(process_list) + 1;
    char *list_copy = (char *)malloc(len);
    if (!list_copy) return FALSE;

    strncpy(list_copy, process_list, len);
    BOOL matched = FALSE;
    char *token = strtok(list_copy, ",;");
    while (token != NULL) {
        // Remove leading whitespace
        while (*token == ' ' || *token == '\t') token++;
        
        // Remove trailing whitespace ( fix)
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0'; end--;
        }

        // Remove quotes "C:\path\app.exe"
        if (*token == '"' && strlen(token) > 1) {
            token++;
            char *quote = strchr(token, '"');
            if (quote != NULL) *quote = '\0';
        }

        if (match_process_pattern(token, process_name)) {
            matched = TRUE; break;
        }
        token = strtok(NULL, ",;");
    }
    free(list_copy); return matched;
}

BOOL is_broadcast_or_multicast(UINT32 ip) {
    if (ip == 0xFFFFFFFF) return TRUE;
    BYTE first = (ip >> 0) & 0xFF;
    if (first == 127) return TRUE; // Localhost
    if (first == 169 && ((ip >> 8) & 0xFF) == 254) return TRUE; // APIPA
    if ((ip & 0xFF000000) == 0xFF000000) return TRUE; // Subnet Broadcast
    if (first >= 224 && first <= 239) return TRUE; // Multicast
    return FALSE;
}