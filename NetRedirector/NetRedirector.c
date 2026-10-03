// --- START OF FILE NetRedirector.c ---
#define WIN32_LEAN_AND_MEAN
#include "NR_Common.h"
#include "NetRedirector.h"
#include "NR_Utils.h"
#include "NR_State.h"
#include "NR_Core.h"
#include "NR_RuleEngine.h"
#include "NR_Protocol.h"
#include "NR_PidMap.h"   // [Added] socket-event pid map (optional fast path)

// Forward Declarations to prevent implicit declaration warnings
NETREDIRECTOR_API UINT32 NetRedirector_AddRuleWithProxy(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);
NETREDIRECTOR_API BOOL NetRedirector_EditRuleWithProxy(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);
static void signal_dns_refresh(void);   // [Added] wake the background DNS refresher (defined above NetRedirector_Start)
static void flush_dns_if_domain_hosts(const char *hosts_field);   // [Added] OS resolver flush for rules that carry a domain (defined above NetRedirector_Start)

// === Global Variable Definitions ===
// Per-structure locks (see NR_Common.h for the ordering rule).
CRITICAL_SECTION lock_rules;
CRITICAL_SECTION lock_connections;
CRITICAL_SECTION lock_logged;
CRITICAL_SECTION lock_proxies;
CRITICAL_SECTION lock_udp;
CRITICAL_SECTION lock_pid_cache;

BOOL running = FALSE;
DWORD g_current_process_id = 0;
HANDLE g_stop_event = NULL;   // manual-reset; wakes sleeping worker threads on Stop

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
    // [Fixed] 清空結構: 名稱規則的 target_pid 必須為 0, 否則 match_rule 會把它當成
    // PID 規則而跳過名稱比對 -> 規則永不匹配, 流量全部走 DIRECT (重大 bug)
    memset(rule, 0, sizeof(PROCESS_RULE));

    rule->rule_id = (UINT32)InterlockedIncrement((volatile LONG*)&g_next_rule_id);  // [Fixed] 原子遞增, 避免多執行緒拿到相同 ID
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

    EnterCriticalSection(&lock_rules); // Optional if single thread config, but safer
    rule->next = rules_list;
    rules_list = rule;
    LeaveCriticalSection(&lock_rules);

    signal_dns_refresh();   // [Added] resolve domain patterns in target_hosts right away
    flush_dns_if_domain_hosts(rule->target_hosts);   // [Added] force an on-the-wire resolve
    return rule->rule_id;
}

NETREDIRECTOR_API UINT32 NetRedirector_AddRuleByPID(DWORD pid, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (!rule) return 0;
    memset(rule, 0, sizeof(PROCESS_RULE));  // [Fixed] 清空結構, 避免未初始化欄位

    rule->rule_id = (UINT32)InterlockedIncrement((volatile LONG*)&g_next_rule_id);  // [Fixed] 原子遞增, 避免多執行緒拿到相同 ID
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

    EnterCriticalSection(&lock_rules);
    rule->next = rules_list;
    rules_list = rule;
    LeaveCriticalSection(&lock_rules);

    signal_dns_refresh();   // [Added] resolve domain patterns in target_hosts right away
    flush_dns_if_domain_hosts(rule->target_hosts);   // [Added] force an on-the-wire resolve
    return rule->rule_id;
}

NETREDIRECTOR_API BOOL NetRedirector_EnableRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    BOOL found = FALSE;
    BOOL needs_flush = FALSE;   // [Added] read under the lock, acted on after it
    EnterCriticalSection(&lock_rules);
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) {
            rule->enabled = TRUE;
            needs_flush = hosts_field_has_domain(rule->target_hosts);
            found = TRUE;
            break;
        }
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    if (found) {
        signal_dns_refresh();   // [Added] re-enabled domain rule may need a fresh resolve
        if (needs_flush) {
            flush_dns_resolver_cache();
            log_message("DNS resolver cache flushed: re-enabled domain rule needs an on-the-wire resolve to learn its IP mapping");
        }
    }
    return found;
}

NETREDIRECTOR_API BOOL NetRedirector_DisableRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    BOOL found = FALSE;
    EnterCriticalSection(&lock_rules);
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) { rule->enabled = FALSE; found = TRUE; break; }
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    return found;
}

NETREDIRECTOR_API BOOL NetRedirector_DeleteRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    EnterCriticalSection(&lock_rules);
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *prev = NULL;
    BOOL found = FALSE;

    while (rule) {
        if (rule->rule_id == rule_id) {
            if (prev) prev->next = rule->next;
            else rules_list = rule->next;
            free(rule->target_hosts);
            free(rule->target_ports);
            free(rule);
            log_message("Deleted rule ID: %u", rule_id);
            found = TRUE;
            break;
        }
        prev = rule;
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    return found;
}

NETREDIRECTOR_API BOOL NetRedirector_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    return NetRedirector_EditRuleWithProxy(rule_id, process_name, target_hosts, target_ports, protocol, action, 0);
}

NETREDIRECTOR_API BOOL NetRedirector_EditRuleWithProxy(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    if (rule_id == 0 || !process_name) return FALSE;
    BOOL found = FALSE;
    EnterCriticalSection(&lock_rules);
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
            found = TRUE;
            break;
        }
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    if (found) {
        signal_dns_refresh();   // [Added] hosts may have changed to new domains
        flush_dns_if_domain_hosts(target_hosts);   // [Added] force an on-the-wire resolve
    }
    return found;
}

// === Proxy Config APIs ===

NETREDIRECTOR_API BOOL NetRedirector_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password)
{
    if (!proxy_ip || !proxy_ip[0] || proxy_port == 0) return FALSE;
    if (resolve_hostname(proxy_ip) == 0) return FALSE;

    EnterCriticalSection(&lock_proxies);
    strncpy(g_proxy_ip, proxy_ip, sizeof(g_proxy_ip)-1);
    g_proxy_ip[sizeof(g_proxy_ip)-1] = '\0';   // always null-terminate
    g_proxy_port = proxy_port;
    g_proxy_type = type;
    
    if (username) strncpy(g_proxy_username, username, sizeof(g_proxy_username)-1);
    else g_proxy_username[0] = '\0';
    g_proxy_username[sizeof(g_proxy_username)-1] = '\0';
    
    if (password) strncpy(g_proxy_password, password, sizeof(g_proxy_password)-1);
    else g_proxy_password[0] = '\0';
    g_proxy_password[sizeof(g_proxy_password)-1] = '\0';
    LeaveCriticalSection(&lock_proxies);

    return TRUE;
}

NETREDIRECTOR_API UINT32 NetRedirector_AddProxyConfig(ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled)
{
    if (!proxy_ip || !proxy_ip[0] || proxy_port == 0) return 0;
    if (resolve_hostname(proxy_ip) == 0) return 0;

    PROXY_CONFIG *config = (PROXY_CONFIG *)malloc(sizeof(PROXY_CONFIG));
    if (!config) return 0;

    memset(config, 0, sizeof(PROXY_CONFIG));
    config->proxy_id = (UINT32)InterlockedIncrement((volatile LONG*)&g_next_proxy_id);  // [Fixed] 原子遞增
    config->proxy_type = type;
    config->proxy_port = proxy_port;
    config->enabled = enabled;
    strncpy(config->proxy_ip, proxy_ip, sizeof(config->proxy_ip)-1);
    config->proxy_ip[sizeof(config->proxy_ip)-1] = '\0';
    
    if (name && name[0]) {
        strncpy(config->name, name, sizeof(config->name)-1);
        config->name[sizeof(config->name)-1] = '\0';
    }
    else snprintf(config->name, sizeof(config->name), "Proxy %u", config->proxy_id);

    if (username) {
        strncpy(config->username, username, sizeof(config->username)-1);
        config->username[sizeof(config->username)-1] = '\0';
    }
    else config->username[0] = 0;

    if (password) {
        strncpy(config->password, password, sizeof(config->password)-1);
        config->password[sizeof(config->password)-1] = '\0';
    }
    else config->password[0] = 0;

    EnterCriticalSection(&lock_proxies);
    config->next = proxy_configs;
    proxy_configs = config;
    LeaveCriticalSection(&lock_proxies);

    log_message("Added proxy config ID: %u", config->proxy_id);
    return config->proxy_id;
}

NETREDIRECTOR_API BOOL NetRedirector_EditProxyConfig(UINT32 proxy_id, ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled)
{
    if (proxy_id == 0) return FALSE;
    
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->proxy_type = type;
        config->proxy_port = proxy_port;
        config->enabled = enabled;
        if (proxy_ip) { strncpy(config->proxy_ip, proxy_ip, sizeof(config->proxy_ip)-1); config->proxy_ip[sizeof(config->proxy_ip)-1] = '\0'; }
        if (name) { strncpy(config->name, name, sizeof(config->name)-1); config->name[sizeof(config->name)-1] = '\0'; }
        if (username) { strncpy(config->username, username, sizeof(config->username)-1); config->username[sizeof(config->username)-1] = '\0'; }
        if (password) { strncpy(config->password, password, sizeof(config->password)-1); config->password[sizeof(config->password)-1] = '\0'; }
        log_message("Updated proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_proxies);
        return TRUE;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DeleteProxyConfig(UINT32 proxy_id)
{
    if (proxy_id == 0) return FALSE;
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = proxy_configs;
    PROXY_CONFIG *prev = NULL;
    while (config) {
        if (config->proxy_id == proxy_id) {
            if (prev) prev->next = config->next;
            else proxy_configs = config->next;
            free(config);
            log_message("Deleted proxy config ID: %u", proxy_id);
            LeaveCriticalSection(&lock_proxies);
            return TRUE;
        }
        prev = config;
        config = config->next;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_EnableProxyConfig(UINT32 proxy_id)
{
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->enabled = TRUE;
        log_message("Enabled proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_proxies);
        return TRUE;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DisableProxyConfig(UINT32 proxy_id)
{
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->enabled = FALSE;
        log_message("Disabled proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_proxies);
        return TRUE;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

// [Added] Toggle socks5h-style remote DNS for one proxy: when enabled, the
// SOCKS5 CONNECT / HTTP CONNECT handshake carries the original hostname
// (recovered from the DNS snoop cache) so the proxy resolves it instead of
// being handed a bare IP.
NETREDIRECTOR_API BOOL NetRedirector_SetProxySendDomain(UINT32 proxy_id, BOOL enable)
{
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->send_domain_to_proxy = enable ? TRUE : FALSE;
        log_message("Proxy config ID %u: remote DNS (socks5h) %s",
                    proxy_id, enable ? "enabled" : "disabled");
        LeaveCriticalSection(&lock_proxies);
        return TRUE;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetProxyConfig(UINT32 proxy_id)
{
    // NOTE: returns an internal pointer without a lock — the caller must not
    // hold the result across concurrent Edit/DeleteProxyConfig calls.
    return (PROXY_CONFIG_API*)get_proxy_by_id(proxy_id);
}

NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetAllProxyConfigs(UINT32* count)
{
    if (count) {
        EnterCriticalSection(&lock_proxies);
        PROXY_CONFIG *c = proxy_configs;
        *count = 0;
        while(c) { (*count)++; c = c->next; }
        LeaveCriticalSection(&lock_proxies);
    }
    return (PROXY_CONFIG_API*)proxy_configs;
}

// === Settings APIs ===

NETREDIRECTOR_API void NetRedirector_SetDnsViaProxy(BOOL enable) { g_dns_via_proxy = enable; }
NETREDIRECTOR_API void NetRedirector_SetUnknownProcessAction(RuleAction action) { g_unknown_process_action = action; }
NETREDIRECTOR_API void NetRedirector_SetLogCallback(LogCallback callback) { g_log_callback = callback; }
NETREDIRECTOR_API void NetRedirector_SetConnectionCallback(ConnectionCallback callback) { g_connection_callback = callback; }

// === Lifecycle APIs ===

// [Added] Background DNS refresher for domain-name rules.
//
// match_ip_pattern() on the packet threads uses resolve_rule_host_cached()
// (cache-only, never blocks). This thread keeps that cache warm: it walks the
// enabled rules, snapshots their hosts fields under lock_rules, then
// re-resolves every domain pattern OUTSIDE any lock (getaddrinfo has no
// timeout and can block for seconds). It wakes immediately when a rule is
// added/edited/enabled (SetEvent) and otherwise refreshes every 30 s, so DNS
// changes propagate well inside the old 60 s TTL window.
static HANDLE dns_refresh_thread_handle = NULL;
static HANDLE dns_refresh_event = NULL;
static volatile BOOL dns_refresh_running = FALSE;

#define DNS_REFRESH_INTERVAL_MS 30000

static void signal_dns_refresh(void)
{
    if (dns_refresh_event != NULL) SetEvent(dns_refresh_event);
}

// [Added] TRUE when at least one ENABLED rule carries a domain pattern. Only
// those rules depend on the DNS-snoop IP->hostname map, so this gates the OS
// resolver cache flush: a setup with no domain rules never pays for it.
static BOOL has_domain_rule(void)
{
    BOOL found = FALSE;
    EnterCriticalSection(&lock_rules);
    for (PROCESS_RULE *r = rules_list; r != NULL; r = r->next) {
        if (r->enabled && hosts_field_has_domain(r->target_hosts)) { found = TRUE; break; }
    }
    LeaveCriticalSection(&lock_rules);
    return found;
}

// [Added] A rule that introduces a domain pattern can only match once the
// hostname has been resolved ON THE WIRE after this point, because that is the
// only thing that feeds the DNS-snoop reverse map (see the long comment on
// flush_dns_resolver_cache in NR_Utils.c). If the app - or any other process -
// already has the answer in the Windows resolver cache, no DNS query is sent,
// the map never learns the IP, and the rule fails SILENTLY (traffic that should
// be proxied goes direct). Flushing forces the next resolution onto the wire.
//
// Rules that carry only IPs or "*" do not benefit, so the flush stays tied to
// the case that actually needs it rather than firing on every rule edit.
static void flush_dns_if_domain_hosts(const char *hosts_field)
{
    if (!hosts_field_has_domain(hosts_field)) return;
    flush_dns_resolver_cache();
    log_message("DNS resolver cache flushed: new domain rule needs an on-the-wire resolve to learn its IP mapping");
}

#define DNS_REFRESH_MAX_RULES 256

static DWORD WINAPI dns_refresh_worker(LPVOID arg)
{
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return 1;

    while (dns_refresh_running) {
        WaitForSingleObject(dns_refresh_event, DNS_REFRESH_INTERVAL_MS);
        if (!dns_refresh_running) break;

        // Snapshot the hosts fields under lock_rules; actual resolution happens
        // outside the lock so rule APIs and packet threads are never blocked.
        char *snapshots[DNS_REFRESH_MAX_RULES];
        int count = 0;
        EnterCriticalSection(&lock_rules);
        PROCESS_RULE *rule = rules_list;
        while (rule != NULL && count < DNS_REFRESH_MAX_RULES) {
            if (rule->enabled && rule->target_hosts) {
                snapshots[count] = _strdup(rule->target_hosts);
                if (snapshots[count] != NULL) count++;
            }
            rule = rule->next;
        }
        LeaveCriticalSection(&lock_rules);

        int i;
        for (i = 0; i < count; i++) {
            if (!dns_refresh_running) break;   // stop early during shutdown
            refresh_rule_dns(snapshots[i]);
        }
        for (i = 0; i < count; i++) free(snapshots[i]);
    }

    WSACleanup();
    return 0;
}

// === Windows 防火牆規則管理 ===
//
// WinDivert 把 NAT 重寫後的封包當作「inbound」重新注入：來源是原始(公開)
// 目的地、目的地是本機的 local relay port。Windows 防火牆(或第三方防火牆)
// 會把這筆視為「從網際網路入站連到 relay port」，在預設的 drop/stealth 姿勢下
// 靜默丟棄 SYN → 所有走代理的連線黑洞，表現就是典型的 ~21 秒 TCP 連線逾時。
// relay 本身 bind 得好好地，pre-flight 的 bind probe 抓不到這種失敗，缺的那一半
// 就是防火牆規則。因此 Start 時替兩個 relay port 加一條入站允許規則，Stop 時移除。
//
// 規則刻意不用 localsubnet 限定：NAT swap 之後注入封包的來源是原始公開目的地，
// 永遠不會是本地位址。relay 只接受「能對上 conntrack 表」的連線(對不上的立刻
// 關閉)，所以放行任意來源入站到這兩個 port 並不會開啟一個可被利用的服務。
//
// 盡力而為(best-effort)：防火牆本來就寬鬆、或使用者已有相同規則的環境，不需要
// 這條規則；失敗只記錄 log，不當成 Start 錯誤(要維持原本寬鬆環境能正常運作)。
static BOOL g_firewall_rule_active = FALSE;

static void run_netsh_firewall(const char *args, BOOL quiet)
{
    char cmdline[512];
    snprintf(cmdline, sizeof(cmdline), "netsh.exe %s", args);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        if (!quiet) log_message("防火牆規則: 無法啟動 netsh (%lu)", GetLastError());
        return;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    if (exit_code != 0) {
        // Deleting a rule that does not exist returns non-zero; that is the
        // expected outcome of the pre-add sweep, not a failure worth logging.
        if (!quiet) log_message("防火牆規則: netsh 回傳 %lu (%s)", exit_code, args);
    } else {
        log_message("防火牆規則已更新: %s", args);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

static void set_relay_firewall_rules(BOOL enable)
{
    if (!enable && !g_firewall_rule_active) return; // 本來就沒加，無需移除

    char cmd[384];
    char tcp_name[64];
    char udp_name[64];
    snprintf(tcp_name, sizeof(tcp_name), "NetRedirector Relay TCP %u", (unsigned)g_local_relay_port);
    snprintf(udp_name, sizeof(udp_name), "NetRedirector Relay UDP %u", (unsigned)LOCAL_UDP_RELAY_PORT);

    if (enable) {
        // [Fixed] Delete before add. netsh "add rule" does NOT replace an
        // existing rule with the same name - it appends another one. Any Start
        // that was not paired with a successful Stop (crash, kill, failed
        // Stop) therefore left its rule behind, and every later Start added one
        // more: the rule table grew without bound. Found on this machine with
        // 118 accumulated rules (59 TCP + 59 UDP). Deleting first makes the
        // operation idempotent, and because "delete rule name=..." removes
        // *every* rule with that name it also sweeps up the existing backlog.
        snprintf(cmd, sizeof(cmd), "advfirewall firewall delete rule name=\"%s\"", tcp_name);
        run_netsh_firewall(cmd, TRUE);
        snprintf(cmd, sizeof(cmd), "advfirewall firewall delete rule name=\"%s\"", udp_name);
        run_netsh_firewall(cmd, TRUE);
    }

    const char *op = enable ? "add" : "delete";

    snprintf(cmd, sizeof(cmd),
        "advfirewall firewall %s rule name=\"%s\" "
        "dir=in action=allow protocol=TCP localport=%u",
        op, tcp_name, (unsigned)g_local_relay_port);
    run_netsh_firewall(cmd, FALSE);

    snprintf(cmd, sizeof(cmd),
        "advfirewall firewall %s rule name=\"%s\" "
        "dir=in action=allow protocol=UDP localport=%u",
        op, udp_name, (unsigned)LOCAL_UDP_RELAY_PORT);
    run_netsh_firewall(cmd, FALSE);

    g_firewall_rule_active = enable;
}

// === WinDivert filter: proxy-endpoint exclusion ===
//
// The relay reaches a proxy over its own TCP/UDP sockets, and every byte of
// proxied traffic crosses them. Those packets match the filter's blanket
// "outbound" clause, are then judged DIRECT (the endpoint is reached directly,
// never through itself), and are re-injected unchanged - so 100% of proxied
// traffic paid a full user-mode round trip (queue -> worker -> checksum ->
// WinDivertSend) for a decision that was always "leave it alone".
//
// The fix reuses the reasoning the loopback exclusion above already applies:
// traffic that is unconditionally DIRECT by policy does not need capturing.
// Only the exact endpoint (address AND port) is excluded, so a legitimate
// connection to the same host on any other port still goes through the proxy -
// excluding by address alone would silently leak such flows to DIRECT.
//
// The filter is fixed when WinDivertOpen is called, so a proxy added or edited
// while running is not excluded until the next Start. That only costs the round
// trip; it is never a correctness problem.
#define MAX_FILTER_ENDPOINTS 8

typedef struct {
    int family;           // AF_INET / AF_INET6
    char ip[MAX_IP_STR];  // canonical literal, safe to embed in a filter
    UINT16 port;
} FILTER_ENDPOINT;

// Collect the enabled proxy endpoints as filter-safe literals. Returns the
// number written. Entries whose address is a hostname (or malformed) are
// skipped: the filter language has no DNS, and emitting an unparseable clause
// would make WinDivertOpen fail, taking the whole Start with it.
static int collect_proxy_endpoints(FILTER_ENDPOINT *out, int max)
{
    int n = 0;
    struct in_addr a4;
    struct in6_addr a6;

    EnterCriticalSection(&lock_proxies);
    for (PROXY_CONFIG *c = proxy_configs; c != NULL && n < max; c = c->next) {
        int family;
        if (!c->enabled || c->proxy_ip[0] == '\0' || c->proxy_port == 0) continue;
        if (InetPtonA(AF_INET, c->proxy_ip, &a4) == 1) family = AF_INET;
        else if (InetPtonA(AF_INET6, c->proxy_ip, &a6) == 1) family = AF_INET6;
        else continue;   // hostname -> cannot be expressed in the filter
        if (InetNtopA(family, (family == AF_INET) ? (const void*)&a4 : (const void*)&a6,
                       out[n].ip, MAX_IP_STR) == NULL) continue;
        out[n].family = family;
        out[n].port = c->proxy_port;
        n++;
    }
    LeaveCriticalSection(&lock_proxies);

    // The legacy single-proxy globals (NetRedirector_SetProxyConfig) live in a
    // different store than the list, so fold them in as well.
    if (n < max && g_proxy_ip[0] != '\0' && g_proxy_port != 0) {
        int family = 0;
        if (InetPtonA(AF_INET, g_proxy_ip, &a4) == 1) family = AF_INET;
        else if (InetPtonA(AF_INET6, g_proxy_ip, &a6) == 1) family = AF_INET6;
        if (family != 0) {
            char ip[MAX_IP_STR];
            if (InetNtopA(family, (family == AF_INET) ? (const void*)&a4 : (const void*)&a6,
                          ip, sizeof(ip)) != NULL) {
                BOOL dup = FALSE;
                for (int i = 0; i < n; i++) {
                    if (out[i].port == g_proxy_port && strcmp(out[i].ip, ip) == 0) { dup = TRUE; break; }
                }
                if (!dup) {
                    out[n].family = family;
                    strncpy(out[n].ip, ip, sizeof(out[n].ip) - 1);
                    out[n].ip[sizeof(out[n].ip) - 1] = '\0';
                    out[n].port = g_proxy_port;
                    n++;
                }
            }
        }
    }
    return n;
}

// Build the WinDivert filter string.
//
// Non-static so tests/test_filter.c can pin its semantics: the exclusions are
// hand-written in De Morgan form (the filter language has no unary NOT), and an
// over-broad exclusion would silently stop proxying a whole class of traffic -
// exactly the failure mode that leaks the host IP.
//
// Two exclusions are applied, both to traffic that is unconditionally DIRECT by
// policy and therefore never needs capturing:
//   1. Loopback (127.0.0.0/8 and ::1). Written as "inbound OR destination is
//      not loopback", evaluated per family. Localhost services used to pay a
//      user-mode round trip per packet for nothing.
//   2. The relay's own tunnel sockets to each proxy endpoint (address AND
//      port). Every byte of proxied traffic crosses these, so capturing them
//      cost a user-mode round trip per packet - queue -> worker -> checksum ->
//      WinDivertSend - for a decision that was always "leave it alone".
//      Matching on the port as well as the address matters: excluding the
//      address alone would stop proxying legitimate connections to that host
//      on any other port.
void build_windivert_filter(char *filter, size_t filter_size)
{
    // [Exclusion 2] Clauses for the relay's own tunnel sockets, in positive
    // (De Morgan) form: "drop the relay's traffic to/from an endpoint" becomes
    // "not addressed to X:Y" AND "not sourced from X:Y". A packet addressed to
    // the endpoint is the relay's tunnel; one sourced from it is its reply.
    char excl_tcp4[1024], excl_udp4[1024], excl_tcp6[1024], excl_udp6[1024];
    excl_tcp4[0] = excl_udp4[0] = excl_tcp6[0] = excl_udp6[0] = '\0';

    FILTER_ENDPOINT endpoints[MAX_FILTER_ENDPOINTS];
    int ep_count = collect_proxy_endpoints(endpoints, MAX_FILTER_ENDPOINTS);
    if (ep_count == MAX_FILTER_ENDPOINTS) {
        log_message("Warning: %d or more enabled proxies; only the first %d are "
            "excluded from capture (the rest cost a user-mode round trip per packet)",
            MAX_FILTER_ENDPOINTS, MAX_FILTER_ENDPOINTS);
    }
    for (int i = 0; i < ep_count; i++) {
        BOOL v4 = (endpoints[i].family == AF_INET);
        const char *ipa = v4 ? "ip" : "ipv6";
        char *tb = v4 ? excl_tcp4 : excl_tcp6;
        char *ub = v4 ? excl_udp4 : excl_udp6;
        size_t tcap = v4 ? sizeof(excl_tcp4) : sizeof(excl_tcp6);
        size_t ucap = v4 ? sizeof(excl_udp4) : sizeof(excl_udp6);
        size_t tlen = strlen(tb);
        size_t ulen = strlen(ub);
        if (tlen + 140 >= tcap || ulen + 140 >= ucap) {
            log_message("Warning: WinDivert exclusion list is full; %s:%u left unexcluded",
                endpoints[i].ip, (unsigned)endpoints[i].port);
            continue;
        }
        snprintf(tb + tlen, tcap - tlen,
            " and (tcp.DstPort != %u or %s.DstAddr != %s)"
            " and (tcp.SrcPort != %u or %s.SrcAddr != %s)",
            (unsigned)endpoints[i].port, ipa, endpoints[i].ip,
            (unsigned)endpoints[i].port, ipa, endpoints[i].ip);
        snprintf(ub + ulen, ucap - ulen,
            " and (udp.DstPort != %u or %s.DstAddr != %s)"
            " and (udp.SrcPort != %u or %s.SrcAddr != %s)",
            (unsigned)endpoints[i].port, ipa, endpoints[i].ip,
            (unsigned)endpoints[i].port, ipa, endpoints[i].ip);
    }
    if (ep_count > 0)
        log_message("WinDivert filter: excluding %d proxy endpoint(s) from capture", ep_count);

    snprintf(filter, filter_size,
        "(ip and ("
        "(tcp and (outbound or tcp.DstPort == %d or tcp.SrcPort == %d)%s) or "
        "(udp and (outbound or udp.DstPort == %d or udp.SrcPort == %d or udp.SrcPort == 53)"
        " and udp.DstPort != 67 and udp.SrcPort != 67"
        " and udp.DstPort != 68 and udp.SrcPort != 68%s))"
        " and (inbound or ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255))"
        " or "
        "(ipv6 and ("
        "(tcp and (outbound or tcp.DstPort == %d or tcp.SrcPort == %d)%s) or "
        "(udp and (outbound or udp.DstPort == %d or udp.SrcPort == %d or udp.SrcPort == 53)"
        // [Fixed] This clause used to carry 67/68 - the IPv4 DHCP ports - copied
        // from the v4 branch. IPv6 has no DHCPv4: DHCPv6 uses client 546 /
        // server 547. Leaving 546/547 unexcluded meant every DHCPv6 renewal was
        // captured and paid a full user-mode round trip (queue -> worker ->
        // checksum -> WinDivertSend). It was never a correctness bug (the rule
        // engine forces multicast/link-local IPv6 to DIRECT), just pure waste.
        " and udp.DstPort != 546 and udp.SrcPort != 546"
        " and udp.DstPort != 547 and udp.SrcPort != 547%s))"
        " and (inbound or ipv6.DstAddr != ::1))",
        g_local_relay_port, g_local_relay_port, excl_tcp4,
        LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT, excl_udp4,
        g_local_relay_port, g_local_relay_port, excl_tcp6,
        LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT, excl_udp6);
}

// [Added] Turn a raw WinDivertOpen() failure code into something the user can
// act on. Previously every failure was reported as a bare number, which tells a
// non-developer nothing. All five mapped codes are ENVIRONMENTAL, not code
// bugs - the fix is always something the user must do on their own machine, so
// the message has to name that action.
static void log_windivert_open_failure(DWORD err)
{
    switch (err) {
    case 2:    // ERROR_FILE_NOT_FOUND
        log_message("Failed to open WinDivert (%lu): WinDivert64.sys not found. "
            "Antivirus commonly quarantines or deletes it - whitelist WinDivert64.sys "
            "and NetRedirector.dll in your AV, then re-extract the app.", err);
        break;
    case 5:    // ERROR_ACCESS_DENIED
        log_message("Failed to open WinDivert (%lu): access denied. The app must run "
            "as Administrator - the WinDivert driver cannot be loaded otherwise.", err);
        break;
    case 577:  // ERROR_INVALID_IMAGE_HASH
        log_message("Failed to open WinDivert (%lu): driver signature verification "
            "failed. WinDivert64.sys may have been modified or is being blocked by "
            "security software. Re-extract it from a trusted copy.", err);
        break;
    case 1058: // ERROR_SERVICE_DISABLED
        log_message("Failed to open WinDivert (%lu): a stale WinDivert service entry "
            "from a previous install is marked disabled. Delete the registry key "
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDivert and retry.", err);
        break;
    case 1275: // ERROR_DRIVER_BLOCKED
        log_message("Failed to open WinDivert (%lu): WinDivert64.sys is blocked by a "
            "Windows security policy or antivirus (BYOVD protection). Whitelist it in "
            "your security software.", err);
        break;
    default:
        log_message("Failed to open WinDivert (%lu): make sure the app is running as "
            "Administrator and that WinDivert64.sys sits next to the executable.", err);
        break;
    }
}

NETREDIRECTOR_API BOOL NetRedirector_Start(void)
{
    // Room for the base filter plus one exclusion pair per proxy endpoint.
    char filter[4096];
    if (running) return FALSE;

    // [Fixed] Pre-flight: verify the local relay port is bindable BEFORE
    // spawning threads. local_proxy_server binds inside its own thread and
    // would otherwise fail silently, leaving Start() reporting success while
    // every proxied connection blackholes. IPv4 bind covers the common case
    // (a dual-stack or IPv4 listener occupying the port).
    //
    // The probe deliberately does NOT set SO_REUSEADDR: a plain bind is the
    // strictest availability test — it fails whenever any socket already
    // holds the port (with or without SO_REUSEADDR). The probe socket is
    // closed immediately afterwards, so the real local_proxy_server bind is
    // unaffected.
    {
        WSADATA wsa_data;
        SOCKET probe = INVALID_SOCKET;
        struct sockaddr_in probe_addr;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return FALSE;
        probe = socket(AF_INET, SOCK_STREAM, 0);
        if (probe == INVALID_SOCKET) {
            log_message("Local relay port probe: socket() failed (%lu); Start aborted",
                WSAGetLastError());
            WSACleanup();
            return FALSE;
        }
        memset(&probe_addr, 0, sizeof(probe_addr));
        probe_addr.sin_family = AF_INET;
        probe_addr.sin_addr.s_addr = INADDR_ANY;
        probe_addr.sin_port = htons((u_short)g_local_relay_port);
        if (bind(probe, (struct sockaddr *)&probe_addr, sizeof(probe_addr)) == SOCKET_ERROR ||
            listen(probe, SOMAXCONN) == SOCKET_ERROR) {
            log_message("Local relay port %d is in use (%lu); Start aborted",
                g_local_relay_port, WSAGetLastError());
            closesocket(probe);
            WSACleanup();
            return FALSE;
        }
        closesocket(probe);

        // [Added] UDP relay pre-flight: udp_relay_server binds inside its own
        // thread and on failure would silently return while Start() reports
        // success - every proxied UDP flow would then blackhole into port
        // %d with no listener. Probe the UDP relay port the same way.
        probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (probe == INVALID_SOCKET) {
            log_message("UDP relay port probe: socket() failed (%lu); Start aborted",
                WSAGetLastError());
            WSACleanup();
            return FALSE;
        }
        probe_addr.sin_port = htons((u_short)LOCAL_UDP_RELAY_PORT);
        if (bind(probe, (struct sockaddr *)&probe_addr, sizeof(probe_addr)) == SOCKET_ERROR) {
            log_message("UDP relay port %d is in use (%lu); Start aborted",
                LOCAL_UDP_RELAY_PORT, WSAGetLastError());
            closesocket(probe);
            WSACleanup();
            return FALSE;
        }
        closesocket(probe);
        WSACleanup();
    }

    running = TRUE;

    // [Added] Stop signal for sleeping worker threads. Created BEFORE any
    // thread that waits on it, closed only after every such thread was joined
    // in Stop(). Manual-reset so a single SetEvent wakes all current waiters.
    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_stop_event == NULL) {
        log_message("Warning: failed to create stop event (%lu); worker threads "
            "fall back to timed Sleep wakeups", GetLastError());
    }

    // Cache local interface addresses for LAN on-link detection
    refresh_local_addresses();

    // Start Cleanup Thread (auxiliary: a failure here is logged, not fatal)
    extern HANDLE cleanup_thread_handle;
    cleanup_thread_handle = CreateThread(NULL, 0, cleanup_thread, NULL, 0, NULL);
    if (!cleanup_thread_handle)
        log_message("Warning: failed to create cleanup thread (%lu)", GetLastError());

    // Start Local Proxy
    proxy_thread = CreateThread(NULL, 0, local_proxy_server, NULL, 0, NULL);
    if (!proxy_thread) {
        log_message("Failed to create local proxy thread (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }

    // Start UDP Relay
    // [Fixed] 修正 CreateThread 堆疊大小: 1 → 0 (0 = 使用系統預設堆疊大小)
    udp_relay_thread = CreateThread(NULL, 0, udp_relay_server, NULL, 0, NULL);
    if (!udp_relay_thread) {
        log_message("Failed to create UDP relay thread (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }

    Sleep(500); // Give servers time to bind

    // Open WinDivert
    //
    // [Fixed] Loopback bypass at the filter layer: 127.0.0.0/8 and ::1 traffic
    // used to be captured and then re-injected unchanged ("captured
    // passthrough") after the upper-layer DIRECT checks. Every localhost
    // packet thus paid a user-mode round trip (queue -> worker -> checksum ->
    // WinDivertSend) and could be delayed or dropped under load - visible as
    // instability for local services (e.g. MySQL on 127.0.0.1) in busy
    // multi-service/Docker environments. Loopback destinations are always
    // DIRECT by policy and never proxied, so excluding them in the filter is
    // semantically identical and removes the entire overhead.
    //
    // The exclusion is written in positive/De Morgan form because the
    // WinDivert filter language has no unary NOT: "keep" = inbound, OR
    // destination-not-loopback, evaluated per family. Verified against the
    // real driver: parses OK and captures zero loopback packets.
    build_windivert_filter(filter, sizeof(filter));

    windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 123, 0);
    if (windivert_handle == INVALID_HANDLE_VALUE) {
        log_windivert_open_failure(GetLastError());
        running = FALSE;
        goto fail;
    }

    // 放行防火牆，讓重寫後 re-inject 回來的 inbound relay 封包能送達本機。
    set_relay_firewall_rules(TRUE);

    // [Added] Start the socket-event pid map before any packet thread exists, so
    // it is warm by the time the first connection is classified. This is an
    // OPTIONAL accelerator: if it fails to start, pid_map_lookup() returns 0 and
    // every process lookup falls back to GetExtendedTcpTable - i.e. the previous
    // behaviour. It must never fail Start().
    pid_map_start();

    // [Added] These are best-effort tuning knobs (16384 and 33553920 are the
    // allowed maxima for the count and byte caps respectively), but a silent
    // failure would leave the queue at the small default and cost throughput
    // under load - leave a trace instead.
    //
    // QUEUE_SIZE is the BYTE cap on the queue, separate from the packet-count
    // cap QUEUE_LENGTH enforces. Without it a burst of large packets can hit
    // the default byte ceiling while the count is still far below 16384, and
    // the driver drops the overflow - TCP then sees loss and halves its
    // congestion window, which reads to the user as "upload is slow".
    //
    // The three calls are deliberately not chained with || : that would skip
    // the later ones as soon as an earlier one failed, and we want every knob
    // attempted and a single honest report if any of them did not take.
    {
        BOOL q_ok = WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
        q_ok = WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000) && q_ok;
        q_ok = WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_SIZE, 33553920) && q_ok;
        if (!q_ok)
            log_message("Warning: WinDivertSetParam failed (%lu); using default queue limits",
                GetLastError());
    }

    // [Modified] Single receiver + flow workers (see NR_Core.c "Flow
    // Dispatch"): the receiver is the only WinDivertRecv caller, so same-flow
    // packets can no longer be re-injected out of order.
    if (!flow_queues_init()) {
        log_message("Failed to initialize flow queues (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }

    packet_threads[0] = CreateThread(NULL, 0, packet_receiver, NULL, 0, NULL);
    if (!packet_threads[0]) {
        log_message("Failed to create packet receiver thread (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }
    for (int i = 1; i < NUM_PACKET_THREADS; i++) {
        packet_threads[i] = CreateThread(NULL, 0, flow_worker, (LPVOID)(LONG_PTR)(i - 1), 0, NULL);
        if (!packet_threads[i]) {
            log_message("Failed to create flow worker thread %d (%lu)", i - 1, GetLastError());
            running = FALSE;
            goto fail;
        }
    }

    // [Added] Domain rules that were configured BEFORE this Start can be
    // silently dead: whatever hostname they target may already sit in the
    // Windows resolver cache (resolved before the rule existed, or before the
    // app was even started), so the application never sends a DNS query, our
    // port-53 snoop never sees the answer, and the IP->hostname map stays empty
    // - the rule matches nothing and the traffic goes direct, with no error
    // anywhere. Flushing forces the next resolution onto the wire where the
    // snoop can observe it. Done BEFORE the refresher thread starts so both
    // paths see the same post-flush world.
    if (has_domain_rule()) {
        flush_dns_resolver_cache();
        log_message("Domain rules present: flushed the Windows DNS resolver cache "
            "so hostnames are re-resolved on the wire and the DNS snoop can map them");
    }

    // [Added] DNS refresher for domain-name rules (keeps resolve_rule_host_
    // cached() warm so packet threads never block in getaddrinfo). Created
    // last: any earlier failure path never has to clean it up.
    dns_refresh_event = CreateEvent(NULL, FALSE, FALSE, NULL);   // auto-reset
    if (dns_refresh_event != NULL) {
        dns_refresh_running = TRUE;
        dns_refresh_thread_handle = CreateThread(NULL, 0, dns_refresh_worker, NULL, 0, NULL);
        if (dns_refresh_thread_handle == NULL) {
            log_message("Warning: failed to create DNS refresh thread (%lu); "
                "domain rules rely on cache primed at resolve time", GetLastError());
            dns_refresh_running = FALSE;
            CloseHandle(dns_refresh_event);
            dns_refresh_event = NULL;
        } else {
            SetEvent(dns_refresh_event);   // resolve existing domain rules immediately
        }
    }

    log_message("NetRedirector started. Relay: %d", g_local_relay_port);
    return TRUE;

fail:
    set_relay_firewall_rules(FALSE);
    pid_map_stop();   // [Added] joins its own consumer thread and closes its handle
    // running is already FALSE, so every server thread exits its loop on its
    // own. Wake the sleepers first (same as Stop), close WinDivert to unblock
    // any packet_processor threads, then wait for and close every handle that
    // was created, and reset all state. (NetRedirector_Stop() cannot be
    // reused here: it guards on `running`.)
    if (g_stop_event != NULL) SetEvent(g_stop_event);
    if (windivert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }
    for (int i = 0; i < NUM_PACKET_THREADS; i++) {
        if (packet_threads[i]) {
            WaitForSingleObject(packet_threads[i], 5000);
            CloseHandle(packet_threads[i]);
            packet_threads[i] = NULL;
        }
    }
    flow_queues_shutdown();
    if (proxy_thread) {
        WaitForSingleObject(proxy_thread, 5000);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
    }
    if (udp_relay_thread) {
        WaitForSingleObject(udp_relay_thread, 5000);
        CloseHandle(udp_relay_thread);
        udp_relay_thread = NULL;
    }
    if (cleanup_thread_handle) {
        WaitForSingleObject(cleanup_thread_handle, 5000);
        CloseHandle(cleanup_thread_handle);
        cleanup_thread_handle = NULL;
    }
    if (g_stop_event) { CloseHandle(g_stop_event); g_stop_event = NULL; }
    clear_connections();
    clear_logged_connections();
    clear_udp_associations();
    clear_pid_cache();
    clear_dns_cache();
    clear_dns_snoop_cache();
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_Stop(void)
{
    if (!running) return FALSE;
    running = FALSE;

    // [Added] Wake the sleeping workers (cleanup thread, DNS refresher)
    // immediately: their wait was previously a 10 s Sleep that could still be
    // running when this function returned and DllMain deleted the locks.
    if (g_stop_event != NULL) SetEvent(g_stop_event);

    if (windivert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }

    // [Added] Stop the socket-event pid map: joins its consumer thread and
    // closes its own (SOCKET-layer) handle. Must happen before the locks are
    // torn down in DllMain, since its thread takes g_lock inside NR_PidMap.c.
    pid_map_stop();

    // [Added] Report what the map actually saved. Without this the feature is
    // invisible from the outside: it either answers or silently falls back, and
    // both look identical in the log. (A fallback is safe by design - see
    // NR_PidMap.h - but the user should be able to see which one is happening.)
    {
        PID_MAP_STATS st;
        pid_map_get_stats(&st);
        if (st.lookups > 0) {
            log_message("PID map: %lu/%lu process lookups served from socket events (%.1f%%), "
                        "%lu ambiguous, %lu events consumed",
                        (unsigned long)st.hits, (unsigned long)st.lookups,
                        100.0 * (double)st.hits / (double)st.lookups,
                        (unsigned long)st.ambiguous, (unsigned long)st.events);
        } else {
            log_message("PID map: no process lookups recorded this session");
        }
    }

    // [Added] Unblock every connection/transfer thread parked in recv(): they
    // observe the shutdown as a closed socket, exit their loops and close
    // their own sockets. Without this they lingered until process exit.
    shutdown_all_connections();

    WaitForMultipleObjects(NUM_PACKET_THREADS, packet_threads, TRUE, 5000);
    for (int i=0; i<NUM_PACKET_THREADS; i++) {
        if(packet_threads[i]) { CloseHandle(packet_threads[i]); packet_threads[i]=NULL; }
    }
    // [Added] Receiver and workers are joined - safe to drain/release queues
    flow_queues_shutdown();

    if (proxy_thread) { WaitForSingleObject(proxy_thread, 5000); CloseHandle(proxy_thread); proxy_thread=NULL; }
    if (udp_relay_thread) { WaitForSingleObject(udp_relay_thread, 5000); CloseHandle(udp_relay_thread); udp_relay_thread=NULL; }
    
    // Extern handle from NR_Core.c
    extern HANDLE cleanup_thread_handle;
    if (cleanup_thread_handle) { WaitForSingleObject(cleanup_thread_handle, 5000); CloseHandle(cleanup_thread_handle); cleanup_thread_handle=NULL; }

    // [Added] Stop the DNS refresher: wake it from the wait, let it observe
    // dns_refresh_running == FALSE and exit. If it is stuck inside a slow
    // getaddrinfo the 5 s wait simply gives up (same policy as the other
    // threads above).
    if (dns_refresh_thread_handle) {
        dns_refresh_running = FALSE;
        signal_dns_refresh();
        WaitForSingleObject(dns_refresh_thread_handle, 5000);
        CloseHandle(dns_refresh_thread_handle);
        dns_refresh_thread_handle = NULL;
    }
    if (dns_refresh_event) { CloseHandle(dns_refresh_event); dns_refresh_event = NULL; }

    // [Added] Every thread that waits on the stop event has been joined by
    // now - safe to release it.
    if (g_stop_event) { CloseHandle(g_stop_event); g_stop_event = NULL; }

    clear_connections();
    clear_logged_connections();
    clear_udp_associations(); // Clean sockets
    clear_pid_cache();        // Drop stale PID/process-name cache entries
    clear_dns_cache();        // [Added] Drop stale domain-rule DNS resolution cache
    clear_dns_snoop_cache();  // [Added] Drop stale DNS-snoop IP->domain cache
    set_relay_firewall_rules(FALSE);   // 移除 relay 入站允許規則

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
            InitializeCriticalSection(&lock_rules);
            InitializeCriticalSection(&lock_connections);
            InitializeCriticalSection(&lock_logged);
            InitializeCriticalSection(&lock_proxies);
            InitializeCriticalSection(&lock_udp);
            InitializeCriticalSection(&lock_pid_cache);
            break;

        case DLL_PROCESS_DETACH:
            // [Fixed] Loader-lock deadlock: during process termination
            // (lpReserved != NULL) the loader holds the loader lock, and
            // NetRedirector_Stop() waits on threads that may be calling
            // CreateThread (connection_handler -> transfer_handler), which
            // itself needs the loader lock -> deadlock. Only run the full
            // stop for an explicit FreeLibrary unload; at process exit the OS
            // is tearing all threads down anyway, so just flag stopped and
            // release memory.
            if (lpReserved == NULL && running) NetRedirector_Stop();
            else running = FALSE;
            
            // Clean global lists
            while (rules_list) {
                PROCESS_RULE *n = rules_list->next;
                free(rules_list->target_hosts); free(rules_list->target_ports); free(rules_list);
                rules_list = n;
            }
            clear_proxy_configs();
            
            DeleteCriticalSection(&lock_rules);
            DeleteCriticalSection(&lock_connections);
            DeleteCriticalSection(&lock_logged);
            DeleteCriticalSection(&lock_proxies);
            DeleteCriticalSection(&lock_udp);
            DeleteCriticalSection(&lock_pid_cache);
            break;
    }
    return TRUE;
}