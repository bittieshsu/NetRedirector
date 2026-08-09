// --- FILE: NR_Utils.c ---
#include "NR_Utils.h"
#include <ws2tcpip.h> // [Added] for getaddrinfo

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

// [Preserved] Process ID retrieval logic (though  didn't improve it, keep as is)
DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port) {
    MIB_TCPTABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0; DWORD pid = 0;
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
    free(tcp_table); return pid;
}

DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port) {
    MIB_UDPTABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0; DWORD pid = 0;
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
    free(udp_table); return pid;
}

// === IPv6 Process ID lookup ===
DWORD get_process_id_from_connection6(const UINT8 *src_ip6, UINT16 src_port) {
    MIB_TCP6TABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0; DWORD pid = 0;
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
    free(tcp_table); return pid;
}

DWORD get_process_id_from_udp_connection6(const UINT8 *src_ip6, UINT16 src_port) {
    MIB_UDP6TABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0; DWORD pid = 0;
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
    free(udp_table); return pid;
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
    HANDLE hProcess; char full_path[MAX_PATH]; DWORD path_len = MAX_PATH;
    if (pid == 0) return FALSE;
    if (pid == 4) { strncpy(name, "System", name_size - 1); return TRUE; } // Small improvement in : System process
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    if (QueryFullProcessImageNameA(hProcess, 0, full_path, &path_len)) {
        strncpy(name, full_path, name_size - 1);
        name[name_size - 1] = '\0';
        CloseHandle(hProcess); return TRUE;
    }
    CloseHandle(hProcess); return FALSE;
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