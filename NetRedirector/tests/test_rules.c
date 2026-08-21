// --- TEST: 規則 CRUD + match_rule 比對行為 ---
#include "test_framework.h"
#include "NR_RuleEngine.h"
#include "NR_Utils.h"
#include "NetRedirector.h"

static UINT8 dst8[16] = {8, 8, 8, 8};
static UINT8 dst6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static RuleAction match4(UINT32 pid, const char *name, UINT16 port, BOOL is_udp, UINT32 *out_pid) {
    return match_rule(pid, name, AF_INET, dst8, port, is_udp, out_pid);
}

int main(void)
{
    init_locks();

    printf("== 無規則時一律 DIRECT ==\n");
    {
        UINT32 out = 99;
        CHECK(match4(100, "chrome.exe", 443, FALSE, &out) == RULE_ACTION_DIRECT, "no rules -> DIRECT");
        CHECK(out == 0, "proxy id reset to 0");
    }

    printf("== 萬用字元規則 (半形/ANY/全形) ==\n");
    {
        UINT32 r1 = NetRedirector_AddRuleWithProxy("*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 1);
        UINT32 out = 0;
        CHECK(match4(100, "chrome.exe", 443, FALSE, &out) == RULE_ACTION_PROXY, "ASCII * -> PROXY");
        CHECK(out == 1, "proxy id = 1");
        NetRedirector_DeleteRule(r1);

        UINT32 r2 = NetRedirector_AddRuleWithProxy("ANY", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 2);
        out = 0;
        CHECK(match4(100, "firefox.exe", 80, FALSE, &out) == RULE_ACTION_PROXY, "ANY -> PROXY");
        CHECK(out == 2, "proxy id = 2");
        NetRedirector_DeleteRule(r2);

        // 全形 ＊ (U+FF0A, UTF-8 EF BC 8A) — 中文輸入法案例
        UINT32 r3 = NetRedirector_AddRuleWithProxy("\xEF\xBC\x8A", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 3);
        out = 0;
        CHECK(match4(100, "game.exe", 9999, FALSE, &out) == RULE_ACTION_PROXY, "full-width ＊ -> PROXY");
        CHECK(out == 3, "proxy id = 3");
        NetRedirector_DeleteRule(r3);
    }

    printf("== 名稱規則 + IP/Port 過濾 ==\n");
    {
        UINT32 r = NetRedirector_AddRuleWithProxy("chrome.exe", "8.8.8.8", "443", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 5);
        UINT32 out = 0;
        CHECK(match4(100, "chrome.exe", 443, FALSE, &out) == RULE_ACTION_PROXY, "chrome->8.8.8.8:443 TCP -> PROXY");
        CHECK(match4(100, "chrome.exe", 80, FALSE, &out) == RULE_ACTION_DIRECT, "port 80 -> DIRECT (no match)");
        CHECK(match4(100, "firefox.exe", 443, FALSE, &out) == RULE_ACTION_DIRECT, "name mismatch -> DIRECT");
        CHECK(match4(100, "chrome.exe", 443, TRUE, &out) == RULE_ACTION_DIRECT, "UDP 不匹配 TCP-only 規則");
        NetRedirector_DeleteRule(r);
    }

    printf("== PID 規則優先於名稱規則 ==\n");
    {
        NetRedirector_AddRuleWithProxy("chrome.exe", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0);
        UINT32 rp = NetRedirector_AddRuleByPID(1234, "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 6);
        UINT32 out = 0;
        CHECK(match4(1234, "chrome.exe", 443, FALSE, &out) == RULE_ACTION_PROXY, "PID 規則優先 -> PROXY");
        CHECK(out == 6, "proxy id = 6");
        CHECK(match4(9999, "chrome.exe", 443, FALSE, &out) == RULE_ACTION_DIRECT, "非目標 PID -> 名稱規則 DIRECT");
        NetRedirector_DeleteRule(rp);
        // 清理名稱規則
        EnterCriticalSection(&lock_rules);
        while (rules_list) {
            PROCESS_RULE *tmp = rules_list->next;
            free(rules_list->target_hosts);
            free(rules_list->target_ports);
            free(rules_list);
            rules_list = tmp;
        }
        LeaveCriticalSection(&lock_rules);
    }

    printf("== Enable/Disable ==\n");
    {
        UINT32 r = NetRedirector_AddRuleWithProxy("*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 1);
        CHECK(NetRedirector_DisableRule(r) == TRUE, "DisableRule");
        UINT32 out = 0;
        CHECK(match4(100, "x.exe", 80, FALSE, &out) == RULE_ACTION_DIRECT, "disabled rule -> DIRECT");
        CHECK(NetRedirector_EnableRule(r) == TRUE, "EnableRule");
        CHECK(match4(100, "x.exe", 80, FALSE, &out) == RULE_ACTION_PROXY, "enabled rule -> PROXY");
        NetRedirector_DeleteRule(r);
    }

    printf("== EditRuleWithProxy 保留 ID ==\n");
    {
        UINT32 r = NetRedirector_AddRuleWithProxy("a.exe", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0);
        CHECK(NetRedirector_EditRuleWithProxy(r, "b.exe", "*", "443", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 8) == TRUE, "EditRuleWithProxy");
        UINT32 out = 0;
        CHECK(match4(100, "b.exe", 443, FALSE, &out) == RULE_ACTION_PROXY, "edited name/action matched");
        CHECK(out == 8, "edited proxy id");
        CHECK(match4(100, "a.exe", 443, FALSE, &out) == RULE_ACTION_DIRECT, "old name no longer matches");
        CHECK(NetRedirector_EditRuleWithProxy(99999, "x.exe", "*", "*", 2, 1, 0) == FALSE, "edit nonexistent -> FALSE");
        NetRedirector_DeleteRule(r);
    }

    return test_summary("test_rules");
}
