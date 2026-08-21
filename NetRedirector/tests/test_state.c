// --- TEST: NR_State 連線狀態追蹤 + 代理設定 ---
#include "test_framework.h"
#include "NR_State.h"
#include "NR_Utils.h"
#include "NetRedirector.h"

int main(void)
{
    init_locks();

    printf("== add/get/is_tracked/remove connection ==\n");
    {
        UINT8 src[16] = {192, 168, 1, 10};
        UINT8 dst[16] = {8, 8, 8, 8};
        UINT16 port = 43210;

        CHECK(is_connection_tracked(port) == FALSE, "not tracked initially");
        add_connection(port, AF_INET, src, dst, 443, 7, RULE_ACTION_PROXY);
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
        add_connection(1000, AF_INET, src, dst, 53, 3, RULE_ACTION_DIRECT);
        UINT8 dst2[16] = {2, 2, 2, 2};
        add_connection(1000, AF_INET, src, dst2, 443, 9, RULE_ACTION_PROXY);  // 同 port 更新
        UINT32 pid = 0;
        UINT16 dport = 0;
        get_connection(1000, NULL, NULL, &dport, &pid, NULL);
        CHECK(dport == 443, "updated dest port");
        CHECK(pid == 9, "updated proxy id");
        remove_connection(1000);
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
