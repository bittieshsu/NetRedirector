// --- START OF FILE NR_State.c ---
#include "NR_State.h"

// Define Global Lists
CONNECTION_INFO *connection_list = NULL;
LOGGED_CONNECTION *logged_connections = NULL;
PROCESS_RULE *rules_list = NULL;
UDP_ASSOCIATION *udp_associations = NULL;
PROXY_CONFIG *proxy_configs = NULL;

// Define ID Counters
UINT32 g_next_rule_id = 1;
UINT32 g_next_proxy_id = 1;

// === Connection Tracking ===

void add_connection(UINT16 src_port, int family, const UINT8 *src_addr, const UINT8 *dest_addr, UINT16 dest_port, UINT32 proxy_id, RuleAction action)
{
    EnterCriticalSection(&lock_cs);

    CONNECTION_INFO *existing = connection_list;
    while (existing != NULL) {
        if (existing->src_port == src_port) {
            existing->family = family;
            if (src_addr) memcpy(existing->src_addr, src_addr, 16);
            if (dest_addr) memcpy(existing->orig_dest_addr, dest_addr, 16);
            existing->orig_dest_port = dest_port;
            existing->proxy_id = proxy_id;
            existing->action = action;
            existing->last_activity = GetTickCount();
            LeaveCriticalSection(&lock_cs);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        LeaveCriticalSection(&lock_cs);
        return;
    }

    conn->src_port = src_port;
    conn->family = family;
    memset(conn->src_addr, 0, 16);
    memset(conn->orig_dest_addr, 0, 16);
    if (src_addr) memcpy(conn->src_addr, src_addr, 16);
    if (dest_addr) memcpy(conn->orig_dest_addr, dest_addr, 16);
    conn->orig_dest_port = dest_port;
    conn->proxy_id = proxy_id;
    conn->action = action;
    conn->last_activity = GetTickCount();
    conn->next = connection_list;
    connection_list = conn;
    LeaveCriticalSection(&lock_cs);
}

BOOL get_connection(UINT16 src_port, int *family, UINT8 *dest_addr, UINT16 *dest_port, UINT32 *proxy_id, RuleAction *action)
{
    BOOL found = FALSE;
    EnterCriticalSection(&lock_cs);
    CONNECTION_INFO *conn = connection_list;
    CONNECTION_INFO *prev = NULL;

    while (conn != NULL)
    {
        if (conn->src_port == src_port)
        {
            if (family) *family = conn->family;
            if (dest_addr) memcpy(dest_addr, conn->orig_dest_addr, 16);
            if (dest_port) *dest_port = conn->orig_dest_port;
            if (proxy_id) *proxy_id = conn->proxy_id;
            if (action) *action = conn->action;
            
            conn->last_activity = GetTickCount();
            found = TRUE;

            // Move to front optimization
            if (prev != NULL)
            {
                prev->next = conn->next;
                conn->next = connection_list;
                connection_list = conn;
            }
            break;
        }
        prev = conn;
        conn = conn->next;
    }
    LeaveCriticalSection(&lock_cs);
    return found;
}

BOOL is_connection_tracked(UINT16 src_port)
{
    BOOL tracked = FALSE;
    EnterCriticalSection(&lock_cs);
    CONNECTION_INFO *conn = connection_list;
    CONNECTION_INFO *prev = NULL;
    while (conn != NULL) {
        if (conn->src_port == src_port) {
            tracked = TRUE;
            // Move to front: this is on the per-packet hot path for UDP relay
            // traffic; keeping frequently-used sockets near the head makes the
            // common case O(1) instead of O(n).
            if (prev != NULL) {
                prev->next = conn->next;
                conn->next = connection_list;
                connection_list = conn;
            }
            break;
        }
        prev = conn;
        conn = conn->next;
    }
    LeaveCriticalSection(&lock_cs);
    return tracked;
}

void remove_connection(UINT16 src_port)
{
    EnterCriticalSection(&lock_cs);
    CONNECTION_INFO **conn_ptr = &connection_list;
    while (*conn_ptr != NULL)
    {
        if ((*conn_ptr)->src_port == src_port)
        {
            CONNECTION_INFO *to_free = *conn_ptr;
            *conn_ptr = (*conn_ptr)->next;
            free(to_free);
            break;
        }
        conn_ptr = &(*conn_ptr)->next;
    }
    LeaveCriticalSection(&lock_cs);
}

void clear_connections()
{
    EnterCriticalSection(&lock_cs);
    while (connection_list != NULL)
    {
        CONNECTION_INFO *to_free = connection_list;
        connection_list = connection_list->next;
        free(to_free);
    }
    LeaveCriticalSection(&lock_cs);
}

// === Logged Connections ===

BOOL is_connection_already_logged(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action)
{
    BOOL found = FALSE;
    EnterCriticalSection(&lock_cs);
    LOGGED_CONNECTION *logged = logged_connections;
    while (logged != NULL)
    {
        if (logged->pid == pid &&
            logged->family == family &&
            memcmp(logged->dest_addr, dest_addr, 16) == 0 &&
            logged->dest_port == dest_port &&
            logged->action == action)
        {
            found = TRUE;
            break;
        }
        logged = logged->next;
    }
    LeaveCriticalSection(&lock_cs);
    return found;
}

void add_logged_connection(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action)
{
    EnterCriticalSection(&lock_cs);
    LOGGED_CONNECTION *logged = (LOGGED_CONNECTION *)malloc(sizeof(LOGGED_CONNECTION));
    if (logged != NULL)
    {
        logged->pid = pid;
        logged->family = family;
        memcpy(logged->dest_addr, dest_addr, 16);
        logged->dest_port = dest_port;
        logged->action = action;
        logged->next = logged_connections;
        logged_connections = logged;
    }
    LeaveCriticalSection(&lock_cs);
}

void clear_logged_connections()
{
    EnterCriticalSection(&lock_cs);
    while (logged_connections != NULL)
    {
        LOGGED_CONNECTION *to_free = logged_connections;
        logged_connections = logged_connections->next;
        free(to_free);
    }
    LeaveCriticalSection(&lock_cs);
}

// === Proxy Configs ===

PROXY_CONFIG* get_proxy_by_id(UINT32 proxy_id)
{
    // Note: Caller usually holds lock, or we should lock here. 
    // Since this returns a pointer that might be used after unlock, allow concurrency carefully.
    // In this project, get_proxy_by_id is called mostly within locked contexts or locally.
    // We will assume the caller handles locking if they need strict safety, 
    // OR we iterate linearly.
    
    PROXY_CONFIG *config = proxy_configs;
    while (config != NULL)
    {
        if (config->proxy_id == proxy_id)
        {
            return config;
        }
        config = config->next;
    }
    return NULL;
}

void clear_proxy_configs()
{
    EnterCriticalSection(&lock_cs);
    while (proxy_configs != NULL)
    {
        PROXY_CONFIG *to_free = proxy_configs;
        proxy_configs = proxy_configs->next;
        free(to_free);
    }
    LeaveCriticalSection(&lock_cs);
}

// === UDP Associations ===

void add_udp_association(UDP_ASSOCIATION* assoc)
{
    EnterCriticalSection(&lock_cs);
    assoc->next = udp_associations;
    udp_associations = assoc;
    LeaveCriticalSection(&lock_cs);
}

void clear_udp_associations()
{
    EnterCriticalSection(&lock_cs);
    while (udp_associations != NULL)
    {
        UDP_ASSOCIATION *to_free = udp_associations;
        udp_associations = udp_associations->next;
        closesocket(to_free->control_socket);
        closesocket(to_free->udp_socket);
        free(to_free);
    }
    LeaveCriticalSection(&lock_cs);
}