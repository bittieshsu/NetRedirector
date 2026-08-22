// --- TEST: NR_State 連線狀態追蹤 + 代理設定 ---
#include "test_framework.h"
#include "NR_State.h"
#include "NR_Utils.h"
#include "NetRedirector.h"

int main(void)
{
    init_locks();

    printf("== add/get/is_tracked/remove connection (TCP) ==\n");
    {
        UINT8 src[16] = {192, 168, 1, 10};
        UINT8 dst[16] = {8, 8, 8, 8};
        UINT16 port = 43210;

        CHECK(is_connection_tracked(port) == FALSE, "not tracked initially");
        add_connection(port, AF_INET, src, dst, 443, 7, RULE_ACTION_PROXY, FALSE);
        CHECK(is_connection_tracked(port) == TRUE, "tracked after add");

        int family = 0;
        UINT8 got_dst[16] = {0};
        UINT16 got_dport = 0;
        UINT32 got_pid = 0;
        RuleAction got_action = RULE_ACTION_DIRECT;
        CHECK(get_connection(port, &family, got_dst, &got_dport, &got_pid, &got_action) == TRUE, "get_connection found");
        CHECK(family == AF_INET, "family preserved");
        CHECK(memcmp(got_dst, dst, 4) == 0, "dest addr preserved");
        CHECK(got_dport == 443, "dest port preserved");
        CHECK(got_pid == 7, "proxy id preserved");
        CHECK(got_action == RULE_ACTION_PROXY, "action preserved");

        remove_connection(port);
        CHECK(is_connection_tracked(port) == FALSE, "untracked after remove");
        CHECK(get_connection(port, NULL, NULL, NULL, NULL, NULL) == FALSE, "get after remove -> FALSE");
    }

    printf("== add_connection 更新既有項目 ==\n");
    {
        UINT8 src[16] = {0};
        UINT8 dst[16] = {1, 1, 1, 1};
        add_connection(1000, AF_INET, src, dst, 53, 3, RULE_ACTION_DIRECT, FALSE);
        UINT8 dst2[16] = {2, 2, 2, 2};
        add_connection(1000, AF_INET, src, dst2, 443, 9, RULE_ACTION_PROXY, FALSE);  // 同 port 更新
        UINT32 pid = 0;
        UINT16 dport = 0;
        get_connection(1000, NULL, NULL, &dport, &pid, NULL);
        CHECK(dport == 443, "updated dest port");
        CHECK(pid == 9, "updated proxy id");
        remove_connection(1000);
    }

    printf("== UDP 多目的地 (同 socket 送多個伺服器) ==\n");
    {
        UINT8 src[16] = {192, 168, 1, 10};
        UINT8 dns1[16] = {8, 8, 8, 8};
        UINT8 dns2[16] = {1, 1, 1, 1};
        UINT16 port = 53210;

        // 同一個 UDP socket 先後送 8.8.8.8:53 與 1.1.1.1:53 (不同代理)
        add_connection(port, AF_INET, src, dns1, 53, 7, RULE_ACTION_PROXY, TRUE);
        add_connection(port, AF_INET, src, dns2, 53, 8, RULE_ACTION_PROXY, TRUE);

        // 兩個目的地各自追蹤,不互相覆蓋
        CHECK(is_connection_tracked_udp(port, AF_INET, dns1) == TRUE, "dest1 tracked");
        CHECK(is_connection_tracked_udp(port, AF_INET, dns2) == TRUE, "dest2 tracked");
        CHECK(is_connection_tracked_udp(port, AF_INET, src) == FALSE, "unknown dest not tracked");

        UINT16 dport = 0;
        UINT32 proxy_id = 0;
        UINT8 got_dest[16] = {0};
        CHECK(get_connection_udp(port, AF_INET, dns1, &dport, &proxy_id) == TRUE, "lookup dest1");
        CHECK(proxy_id == 7, "dest1 keeps its own proxy id");
        CHECK(get_connection_udp(port, AF_INET, dns2, &dport, &proxy_id) == TRUE, "lookup dest2");
        CHECK(proxy_id == 8, "dest2 keeps its own proxy id");
        CHECK(get_connection_udp(port, AF_INET6, dns1, &dport, &proxy_id) == FALSE, "family mismatch -> miss");

        // UDP 條目不得被 TCP 查詢/移除路徑誤刪
        CHECK(is_connection_tracked(port) == FALSE, "TCP lookup skips UDP entries");
        remove_connection(port);
        CHECK(is_connection_tracked_udp(port, AF_INET, dns1) == TRUE, "TCP remove keeps UDP entry");

        // 回應改寫用的 per-app-port 查詢: 找得到任一 UDP 條目的目的 port
        CHECK(get_udp_dest_port_for_app(port, &dport) == TRUE, "response rewrite lookup found");
        CHECK(dport == 53, "response rewrite port");
        clear_connections();
        CHECK(get_udp_dest_port_for_app(port, &dport) == FALSE, "cleared -> miss");
    }

    printf("== IPv6 UDP 多目的地 ==\n");
    {
        UINT8 src[16] = {0};
        UINT8 dst6a[16] = {0x20,0x01,0x48,0x60,0,0,0,0,0,0,0,0,0,0,0x88,0x88};  // 2001:4860::8888
        UINT8 dst6b[16] = {0x26,0x02,0x06,0x00,0,0,0,0,0,0,0,0,0,0,0x00,0x10};  // 2606:4700::1110-ish
        UINT16 port = 53211;

        add_connection(port, AF_INET6, src, dst6a, 853, 7, RULE_ACTION_PROXY, TRUE);
        add_connection(port, AF_INET6, src, dst6b, 853, 8, RULE_ACTION_PROXY, TRUE);
        CHECK(is_connection_tracked_udp(port, AF_INET6, dst6a) == TRUE, "v6 dest1 tracked");
        CHECK(is_connection_tracked_udp(port, AF_INET6, dst6b) == TRUE, "v6 dest2 tracked");

        UINT32 proxy_id = 0;
        CHECK(get_connection_udp(port, AF_INET6, dst6a, NULL, &proxy_id) == TRUE, "v6 dest1 lookup");
        CHECK(proxy_id == 7, "v6 dest1 proxy id");
        CHECK(get_connection_udp(port, AF_INET6, dst6b, NULL, &proxy_id) == TRUE, "v6 dest2 lookup");
        CHECK(proxy_id == 8, "v6 dest2 proxy id");
        clear_connections();
    }

    printf("== logged connections ==\n");
    {
        UINT8 dst[4] = {9, 9, 9, 9};
        CHECK(is_connection_already_logged(1234, AF_INET, dst, 443, RULE_ACTION_PROXY) == FALSE, "not logged initially");
        add_logged_connection(1234, AF_INET, dst, 443, RULE_ACTION_PROXY);
        CHECK(is_connection_already_logged(1234, AF_INET, dst, 443, RULE_ACTION_PROXY) == TRUE, "logged after add");
        clear_logged_connections();
        CHECK(is_connection_already_logged(1234, AF_INET, dst, 443, RULE_ACTION_PROXY) == FALSE, "cleared");
    }

    printf("== proxy configs (Add/Get/Edit/Delete) ==\n");
    {
        UINT32 pid = NetRedirector_AddProxyConfig(PROXY_TYPE_SOCKS5, "Test", "127.0.0.1", 1080, "u", "p", TRUE);
        CHECK(pid != 0, "AddProxyConfig returns id");
        CHECK(pid == 1, "first proxy id = 1");

        // get_proxy_by_id 契約: 呼叫端須持有 lock_proxies
        EnterCriticalSection(&lock_proxies);
        PROXY_CONFIG *cfg = get_proxy_by_id(pid);
        CHECK(cfg != NULL, "get_proxy_by_id found");
        if (cfg) {
            CHECK(cfg->enabled == TRUE, "enabled flag");
            CHECK(cfg->proxy_port == 1080, "port stored");
            CHECK(strcmp(cfg->proxy_ip, "127.0.0.1") == 0, "ip stored");
        }
        LeaveCriticalSection(&lock_proxies);

        CHECK(NetRedirector_EditProxyConfig(pid, PROXY_TYPE_HTTP, "Test2", "127.0.0.1", 3128, "", "", FALSE) == TRUE, "EditProxyConfig");
        EnterCriticalSection(&lock_proxies);
        cfg = get_proxy_by_id(pid);
        if (cfg) {
            CHECK(cfg->proxy_type == PROXY_TYPE_HTTP, "type updated");
            CHECK(cfg->proxy_port == 3128, "port updated");
            CHECK(cfg->enabled == FALSE, "disabled updated");
        }
        LeaveCriticalSection(&lock_proxies);

        CHECK(NetRedirector_DeleteProxyConfig(pid) == TRUE, "DeleteProxyConfig");
        EnterCriticalSection(&lock_proxies);
        CHECK(get_proxy_by_id(pid) == NULL, "gone after delete");
        LeaveCriticalSection(&lock_proxies);
    }

    return test_summary("test_state");
}
