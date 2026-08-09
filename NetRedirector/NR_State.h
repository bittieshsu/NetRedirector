// --- START OF FILE NR_State.h ---
#ifndef NR_STATE_H
#define NR_STATE_H

#include "NR_Common.h"

// === Global Lists (Defined in NR_State.c) ===
extern CONNECTION_INFO *connection_list;
extern LOGGED_CONNECTION *logged_connections;
extern PROCESS_RULE *rules_list;
extern UDP_ASSOCIATION *udp_associations;
// proxy_configs is already extern in NR_Common.h

// === Connection Tracking ===
void add_connection(UINT16 src_port, int family, const UINT8 *src_addr, const UINT8 *dest_addr, UINT16 dest_port, UINT32 proxy_id, RuleAction action);
BOOL get_connection(UINT16 src_port, int *family, UINT8 *dest_addr, UINT16 *dest_port, UINT32 *proxy_id, RuleAction *action);
BOOL is_connection_tracked(UINT16 src_port);
void remove_connection(UINT16 src_port);
void clear_connections(); // New helper

// === Logged Connections (Deduplication) ===
BOOL is_connection_already_logged(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action);
void add_logged_connection(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action);
void clear_logged_connections();

// === Proxy Config Management ===
PROXY_CONFIG* get_proxy_by_id(UINT32 proxy_id);
void clear_proxy_configs(); // New helper

// === UDP Association Management ===
void add_udp_association(UDP_ASSOCIATION* assoc);
void remove_udp_association(UDP_ASSOCIATION* assoc);
void clear_udp_associations(); // New helper

#endif // NR_STATE_H