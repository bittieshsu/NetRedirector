// --- START OF FILE NetRedirector.h ---
#ifndef NETREDIRECTOR_H
#define NETREDIRECTOR_H

#include <windows.h>

#ifdef NETREDIRECTOR_EXPORTS
#define NETREDIRECTOR_API __declspec(dllexport)
#else
#define NETREDIRECTOR_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Define callbacks
typedef void (*LogCallback)(const char* message);
typedef void (*ConnectionCallback)(const char* process_name, DWORD pid, const char* dest_ip, UINT16 dest_port, const char* proxy_info);

// Enums
typedef enum {
    PROXY_TYPE_HTTP = 0,
    PROXY_TYPE_SOCKS5 = 1
} ProxyType;

typedef enum {
    RULE_ACTION_PROXY = 0,
    RULE_ACTION_DIRECT = 1,
    RULE_ACTION_BLOCK = 2
} RuleAction;

typedef enum {
    RULE_PROTOCOL_TCP = 0,
    RULE_PROTOCOL_UDP = 1,
    RULE_PROTOCOL_BOTH = 2
} RuleProtocol;

// Public Structure for API consumers (Do not expose internal pointers here usually, but keeping compatible with original)
typedef struct PROXY_CONFIG_API {
    UINT32 proxy_id;
    char name[256];
    char proxy_ip[64];
    UINT16 proxy_port;
    ProxyType proxy_type;
    char username[256];
    char password[256];
    BOOL enabled;
    struct PROXY_CONFIG_API *next;
} PROXY_CONFIG_API;

// API Exports

// Rule Management
NETREDIRECTOR_API UINT32 NetRedirector_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action);
NETREDIRECTOR_API UINT32 NetRedirector_AddRuleWithProxy(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);
NETREDIRECTOR_API UINT32 NetRedirector_AddRuleByPID(DWORD pid, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);
NETREDIRECTOR_API BOOL NetRedirector_EnableRule(UINT32 rule_id);
NETREDIRECTOR_API BOOL NetRedirector_DisableRule(UINT32 rule_id);
NETREDIRECTOR_API BOOL NetRedirector_DeleteRule(UINT32 rule_id);
NETREDIRECTOR_API BOOL NetRedirector_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action);
NETREDIRECTOR_API BOOL NetRedirector_EditRuleWithProxy(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);

// Proxy Config Management
NETREDIRECTOR_API BOOL NetRedirector_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password);
NETREDIRECTOR_API UINT32 NetRedirector_AddProxyConfig(ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled);
NETREDIRECTOR_API BOOL NetRedirector_EditProxyConfig(UINT32 proxy_id, ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled);
NETREDIRECTOR_API BOOL NetRedirector_DeleteProxyConfig(UINT32 proxy_id);
NETREDIRECTOR_API BOOL NetRedirector_EnableProxyConfig(UINT32 proxy_id);
NETREDIRECTOR_API BOOL NetRedirector_DisableProxyConfig(UINT32 proxy_id);
NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetProxyConfig(UINT32 proxy_id);
NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetAllProxyConfigs(UINT32* count);

// Settings
NETREDIRECTOR_API void NetRedirector_SetDnsViaProxy(BOOL enable);
NETREDIRECTOR_API void NetRedirector_SetUnknownProcessAction(RuleAction action);
NETREDIRECTOR_API void NetRedirector_SetLogCallback(LogCallback callback);
NETREDIRECTOR_API void NetRedirector_SetConnectionCallback(ConnectionCallback callback);

// Lifecycle
NETREDIRECTOR_API BOOL NetRedirector_Start(void);
NETREDIRECTOR_API BOOL NetRedirector_Stop(void);


#ifdef __cplusplus
}
#endif

#endif // NETREDIRECTOR_H