// --- FILE: NR_Utils.h ---
#ifndef NR_UTILS_H
#define NR_UTILS_H

#include "NR_Common.h"

// Networking & Strings
UINT32 parse_ipv4(const char *ip);
UINT32 resolve_hostname(const char *hostname);
const char* extract_filename(const char* path);
void EnableKeepAlive(SOCKET s);
void base64_encode(const char* input, char* output, size_t output_size);

// Process ID & Name Resolution
DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port);
DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port);
DWORD get_process_id_from_connection6(const UINT8 *src_ip6, UINT16 src_port);
DWORD get_process_id_from_udp_connection6(const UINT8 *src_ip6, UINT16 src_port);
BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);

// IPv6 Helpers
void addr_to_string(int family, const UINT8 *addr, char *buf, size_t size);
BOOL is_multicast_or_special6(const UINT8 *a);

// LAN / On-link Detection
void refresh_local_addresses(void);
BOOL is_lan_or_on_link_address(int family, const UINT8 *addr);

// Matching Logic
BOOL match_ip_pattern(const char *pattern, UINT32 ip);
BOOL match_port_pattern(const char *pattern, UINT16 port);
BOOL match_ip_list(const char *ip_list, UINT32 ip);
BOOL match_port_list(const char *port_list, UINT16 port);
BOOL match_ip_pattern6(const char *pattern, const UINT8 *ip);
BOOL match_ip_list6(const char *ip_list, const UINT8 *ip);
BOOL match_process_pattern(const char *pattern, const char *process_full_path);
BOOL match_process_list(const char *process_list, const char *process_name);
BOOL is_broadcast_or_multicast(UINT32 ip);

#endif // NR_UTILS_H