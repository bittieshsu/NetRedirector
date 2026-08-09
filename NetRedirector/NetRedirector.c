// --- START OF FILE NetRedirector.c ---
#define WIN32_LEAN_AND_MEAN
#include "NR_Common.h"
#include "NetRedirector.h"
#include "NR_Utils.h"
#include "NR_State.h"
#include "NR_Core.h"
#include "NR_RuleEngine.h"
#include "NR_Protocol.h"

// Forward Declarations to prevent implicit declaration warnings
NETREDIRECTOR_API UINT32 NetRedirector_AddRuleWithProxy(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);
NETREDIRECTOR_API BOOL NetRedirector_EditRuleWithProxy(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);

// === Global Variable Definitions ===
CRITICAL_SECTION lock_cs;
BOOL running = FALSE;
DWORD g_current_process_id = 0;

char g_proxy_ip[64] = "";
UINT16 g_proxy_port = 0;
UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
ProxyType g_proxy_type = PROXY_TYPE_SOCKS5;
char g_proxy_username[256] = "";
char g_proxy_password[256] = "";

BOOL g_dns_via_proxy = TRUE;
RuleAction g_unknown_process_action = RULE_ACTION_DIRECT;

LogCallback g_log_callback = NULL;
ConnectionCallback g_connection_callback = NULL;

// Helper to log messages
void log_message(const char *msg, ...)
{
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    g_log_callback(buffer);
}

// === API Implementations ===

NETREDIRECTOR_API UINT32 NetRedirector_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    return NetRedirector_AddRuleWithProxy(process_name, target_hosts, target_ports, protocol, action, 0);
}

NETREDIRECTOR_API UINT32 NetRedirector_AddRuleWithProxy(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    if (!process_name || !process_name[0]) return 0;
    
    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (!rule) return 0;

    rule->rule_id = g_next_rule_id++;
    strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
    rule->process_name[MAX_PROCESS_NAME - 1] = '\0';
    rule->protocol = protocol;
    rule->action = action;
    rule->proxy_id = proxy_id;
    rule->enabled = TRUE;

    // Handle Hosts
    if (target_hosts && target_hosts[0]) rule->target_hosts = _strdup(target_hosts);
    else rule->target_hosts = _strdup("*");

    // Handle Ports
    if (target_ports && target_ports[0]) rule->target_ports = _strdup(target_ports);
    else rule->target_ports = _strdup("*");

    EnterCriticalSection(&lock_cs); // Optional if single thread config, but safer
    rule->next = rules_list;
    rules_list = rule;
    LeaveCriticalSection(&lock_cs);

    return rule->rule_id;
}

NETREDIRECTOR_API UINT32 NetRedirector_AddRuleByPID(DWORD pid, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (!rule) return 0;

    rule->rule_id = g_next_rule_id++;
    rule->target_pid = pid;      // Set PID
    rule->process_name[0] = '\0'; // Name empty for PID-based rules
    rule->protocol = protocol;
    rule->action = action;
    rule->proxy_id = proxy_id;
    rule->enabled = TRUE;

    // Handle Hosts
    if (target_hosts && target_hosts[0]) rule->target_hosts = _strdup(target_hosts);
    else rule->target_hosts = _strdup("*");

    // Handle Ports
    if (target_ports && target_ports[0]) rule->target_ports = _strdup(target_ports);
    else rule->target_ports = _strdup("*");

    EnterCriticalSection(&lock_cs);
    rule->next = rules_list;
    rules_list = rule;
    LeaveCriticalSection(&lock_cs);

    return rule->rule_id;
}

NETREDIRECTOR_API BOOL NetRedirector_EnableRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) { rule->enabled = TRUE; return TRUE; }
        rule = rule->next;
    }
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DisableRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) { rule->enabled = FALSE; return TRUE; }
        rule = rule->next;
    }
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DeleteRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *prev = NULL;

    while (rule) {
        if (rule->rule_id == rule_id) {
            if (prev) prev->next = rule->next;
            else rules_list = rule->next;
            free(rule->target_hosts);
            free(rule->target_ports);
            free(rule);
            log_message("Deleted rule ID: %u", rule_id);
            return TRUE;
        }
        prev = rule;
        rule = rule->next;
    }
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    return NetRedirector_EditRuleWithProxy(rule_id, process_name, target_hosts, target_ports, protocol, action, 0);
}

NETREDIRECTOR_API BOOL NetRedirector_EditRuleWithProxy(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    if (rule_id == 0 || !process_name) return FALSE;
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) {
            strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
            rule->process_name[MAX_PROCESS_NAME-1] = '\0';
            
            if (rule->target_hosts) free(rule->target_hosts);
            rule->target_hosts = _strdup(target_hosts ? target_hosts : "*");

            if (rule->target_ports) free(rule->target_ports);
            rule->target_ports = _strdup(target_ports ? target_ports : "*");

            rule->protocol = protocol;
            rule->action = action;
            rule->proxy_id = proxy_id;
            log_message("Updated rule ID: %u", rule_id);
            return TRUE;
        }
        rule = rule->next;
    }
    return FALSE;
}

// === Proxy Config APIs ===

NETREDIRECTOR_API BOOL NetRedirector_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password)
{
    if (!proxy_ip || !proxy_ip[0] || proxy_port == 0) return FALSE;
    if (resolve_hostname(proxy_ip) == 0) return FALSE;

    strncpy(g_proxy_ip, proxy_ip, sizeof(g_proxy_ip)-1);
    g_proxy_port = proxy_port;
    g_proxy_type = type;
    
    if (username) strncpy(g_proxy_username, username, sizeof(g_proxy_username)-1);
    else g_proxy_username[0] = '\0';
    
    if (password) strncpy(g_proxy_password, password, sizeof(g_proxy_password)-1);
    else g_proxy_password[0] = '\0';

    return TRUE;
}

NETREDIRECTOR_API UINT32 NetRedirector_AddProxyConfig(ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled)
{
    if (!proxy_ip || !proxy_ip[0] || proxy_port == 0) return 0;
    if (resolve_hostname(proxy_ip) == 0) return 0;

    PROXY_CONFIG *config = (PROXY_CONFIG *)malloc(sizeof(PROXY_CONFIG));
    if (!config) return 0;

    config->proxy_id = g_next_proxy_id++;
    config->proxy_type = type;
    config->proxy_port = proxy_port;
    config->enabled = enabled;
    strncpy(config->proxy_ip, proxy_ip, 63);
    
    if (name && name[0]) strncpy(config->name, name, 255);
    else snprintf(config->name, 255, "Proxy %u", config->proxy_id);

    if (username) strncpy(config->username, username, 255);
    else config->username[0] = 0;

    if (password) strncpy(config->password, password, 255);
    else config->password[0] = 0;

    EnterCriticalSection(&lock_cs);
    config->next = proxy_configs;
    proxy_configs = config;
    LeaveCriticalSection(&lock_cs);

    log_message("Added proxy config ID: %u", config->proxy_id);
    return config->proxy_id;
}

NETREDIRECTOR_API BOOL NetRedirector_EditProxyConfig(UINT32 proxy_id, ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled)
{
    if (proxy_id == 0) return FALSE;
    
    EnterCriticalSection(&lock_cs);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->proxy_type = type;
        config->proxy_port = proxy_port;
        config->enabled = enabled;
        if (proxy_ip) strncpy(config->proxy_ip, proxy_ip, 63);
        if (name) strncpy(config->name, name, 255);
        if (username) strncpy(config->username, username, 255);
        if (password) strncpy(config->password, password, 255);
        log_message("Updated proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_cs);
        return TRUE;
    }
    LeaveCriticalSection(&lock_cs);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DeleteProxyConfig(UINT32 proxy_id)
{
    if (proxy_id == 0) return FALSE;
    EnterCriticalSection(&lock_cs);
    PROXY_CONFIG *config = proxy_configs;
    PROXY_CONFIG *prev = NULL;
    while (config) {
        if (config->proxy_id == proxy_id) {
            if (prev) prev->next = config->next;
            else proxy_configs = config->next;
            free(config);
            log_message("Deleted proxy config ID: %u", proxy_id);
            LeaveCriticalSection(&lock_cs);
            return TRUE;
        }
        prev = config;
        config = config->next;
    }
    LeaveCriticalSection(&lock_cs);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_EnableProxyConfig(UINT32 proxy_id)
{
    EnterCriticalSection(&lock_cs);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->enabled = TRUE;
        log_message("Enabled proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_cs);
        return TRUE;
    }
    LeaveCriticalSection(&lock_cs);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DisableProxyConfig(UINT32 proxy_id)
{
    EnterCriticalSection(&lock_cs);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->enabled = FALSE;
        log_message("Disabled proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_cs);
        return TRUE;
    }
    LeaveCriticalSection(&lock_cs);
    return FALSE;
}

NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetProxyConfig(UINT32 proxy_id)
{
    return (PROXY_CONFIG_API*)get_proxy_by_id(proxy_id);
}

NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetAllProxyConfigs(UINT32* count)
{
    if (count) {
        EnterCriticalSection(&lock_cs);
        PROXY_CONFIG *c = proxy_configs;
        *count = 0;
        while(c) { (*count)++; c = c->next; }
        LeaveCriticalSection(&lock_cs);
    }
    return (PROXY_CONFIG_API*)proxy_configs;
}

// === Settings APIs ===

NETREDIRECTOR_API void NetRedirector_SetDnsViaProxy(BOOL enable) { g_dns_via_proxy = enable; }
NETREDIRECTOR_API void NetRedirector_SetUnknownProcessAction(RuleAction action) { g_unknown_process_action = action; }
NETREDIRECTOR_API void NetRedirector_SetLogCallback(LogCallback callback) { g_log_callback = callback; }
NETREDIRECTOR_API void NetRedirector_SetConnectionCallback(ConnectionCallback callback) { g_connection_callback = callback; }

// === Lifecycle APIs ===

NETREDIRECTOR_API BOOL NetRedirector_Start(void)
{
    char filter[512];
    if (running) return FALSE;
    running = TRUE;

    // Start Cleanup Thread
    extern HANDLE cleanup_thread_handle; 
    cleanup_thread_handle = CreateThread(NULL, 0, cleanup_thread, NULL, 0, NULL);

    // Start Local Proxy
    proxy_thread = CreateThread(NULL, 0, local_proxy_server, NULL, 0, NULL);
    if (!proxy_thread) { running = FALSE; return FALSE; }

    // Start UDP Relay
    // [ ץ    I]  N 쥻   1  אּ 0 (0  N  ϥιw ] Stack Size)
    udp_relay_thread = CreateThread(NULL, 0, udp_relay_server, NULL, 0, NULL);
    
    if (!udp_relay_thread) {
        running = FALSE;
        //  T O p G UDP    ѡA n   TCP Proxy  ]    
        WaitForSingleObject(proxy_thread, INFINITE);
        CloseHandle(proxy_thread);
        return FALSE;
    }

    Sleep(500); // Give servers time to bind

    // Open WinDivert
    snprintf(filter, sizeof(filter),
        "(ip or ipv6) and ("
        "(tcp and (outbound or tcp.DstPort == %d or tcp.SrcPort == %d)) or "
        "(udp and (outbound or udp.DstPort == %d or udp.SrcPort == %d) "
        "and udp.DstPort != 67 and udp.SrcPort != 67 and udp.DstPort != 68 and udp.SrcPort != 68)"
        ")",
        g_local_relay_port, g_local_relay_port, 
        LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT);

    windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 123, 0);
    if (windivert_handle == INVALID_HANDLE_VALUE) {
        log_message("Failed to open WinDivert (%lu)", GetLastError());
        //  p G X ʶ} ҥ  ѡA     I s Stop  i 槹  M z
        NetRedirector_Stop();
        return FALSE;
    }

    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000);

    for (int i = 0; i < NUM_PACKET_THREADS; i++) {
        packet_threads[i] = CreateThread(NULL, 0, packet_processor, NULL, 0, NULL);
    }

    log_message("NetRedirector started. Relay: %d", g_local_relay_port);
    return TRUE;
}

NETREDIRECTOR_API BOOL NetRedirector_Stop(void)
{
    if (!running) return FALSE;
    running = FALSE;

    if (windivert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }

    WaitForMultipleObjects(NUM_PACKET_THREADS, packet_threads, TRUE, 5000);
    for (int i=0; i<NUM_PACKET_THREADS; i++) {
        if(packet_threads[i]) { CloseHandle(packet_threads[i]); packet_threads[i]=NULL; }
    }

    if (proxy_thread) { WaitForSingleObject(proxy_thread, 5000); CloseHandle(proxy_thread); proxy_thread=NULL; }
    if (udp_relay_thread) { WaitForSingleObject(udp_relay_thread, 5000); CloseHandle(udp_relay_thread); udp_relay_thread=NULL; }
    
    // Extern handle from NR_Core.c
    extern HANDLE cleanup_thread_handle;
    if (cleanup_thread_handle) { WaitForSingleObject(cleanup_thread_handle, 5000); CloseHandle(cleanup_thread_handle); cleanup_thread_handle=NULL; }

    clear_connections();
    clear_logged_connections();
    clear_udp_associations(); // Clean sockets

    log_message("NetRedirector stopped");
    return TRUE;
}

// === DllMain ===

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            g_current_process_id = GetCurrentProcessId();
            InitializeCriticalSection(&lock_cs);
            break;

        case DLL_PROCESS_DETACH:
            if (running) NetRedirector_Stop();
            
            // Clean global lists
            while (rules_list) {
                PROCESS_RULE *n = rules_list->next;
                free(rules_list->target_hosts); free(rules_list->target_ports); free(rules_list);
                rules_list = n;
            }
            clear_proxy_configs();
            
            DeleteCriticalSection(&lock_cs);
            break;
    }
    return TRUE;
}