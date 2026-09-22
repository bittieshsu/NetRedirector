// --- TEST: UDP relay reply rewrite + response source matching ---
#include "test_framework.h"
#include "NR_Core.h"
#include "NR_State.h"
#include "NR_Utils.h"
#include "NetRedirector.h"

// 說明: 這段決策過去完全在主機端測試之外。實際踩到的 bug 是回程只還原端口、
// 把來源位址留成本機，導致 connect() 的遊戲 socket 丟棄所有回覆。這裡把決策
// 抽成純函式並把行為鎖住，避免同類回歸。
//
// 注意: include 必須放在中文註解之前。MSVC 以 cp950 讀 UTF-8 時，行尾中文字
// 會把下一行併進註解，若該行是 #include 就會整個失效。

int main(void)
{
    init_locks();

    printf("== udp_reply_source: relay reply source must be the real server ==\n");
    {
        UINT8 relay_src[16] = {192, 168, 1, 50, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
        UINT8 app[16]       = {192, 168, 1, 50};
        UINT8 srv[16]       = {203, 0, 113, 7};
        UINT8 out[16] = {0};
        UINT16 out_port = 0;

        CHECK(udp_reply_source(AF_INET, relay_src, 33200, TRUE, srv, 26500, out, &out_port) == TRUE,
              "known remote -> source rewritten");
        CHECK(memcmp(out, srv, 4) == 0, "source is the server address");
        CHECK(memcmp(out, app, 4) != 0, "source is NOT the app itself (regression guard)");
        CHECK(out_port == 26500, "source port is the server port");

        memset(out, 0, sizeof(out)); out_port = 0;
        CHECK(udp_reply_source(AF_INET, relay_src, 33200, FALSE, NULL, 0, out, &out_port) == FALSE,
              "unknown remote -> source left alone");
        CHECK(memcmp(out, relay_src, 4) == 0, "source stays the relay address");
        CHECK(out_port == 33200, "source stays the relay port");
        CHECK(out[4] == 0 && out[8] == 0, "IPv4 writes only the first 4 bytes");
    }

    printf("== udp_reply_source: IPv6 uses the full 16 bytes ==\n");
    {
        UINT8 relay_src[16] = {0};
        UINT8 srv6[16] = {0x20,0x01,0x48,0x60,0,0,0,0,0,0,0,0,0,0,0x88,0x88};
        UINT8 out[16] = {0};
        UINT16 out_port = 0;

        CHECK(udp_reply_source(AF_INET6, relay_src, 33200, TRUE, srv6, 7777, out, &out_port) == TRUE,
              "v6 remote -> source rewritten");
        CHECK(memcmp(out, srv6, 16) == 0, "full 16-byte v6 source copied");
        CHECK(out_port == 7777, "v6 source port");
    }

    printf("== resolve_udp_response: exact match first, port-only fallback ==\n");
    {
        UINT8 app[16]  = {192, 168, 1, 50};
        UINT8 srvA[16] = {203, 0, 113, 7};
        UINT8 srvB[16] = {198, 51, 100, 9};
        UINT16 app_port = 51000;
        UINT16 srv_port = 26500;

        add_connection(app_port, AF_INET, app, srvA, srv_port, 1, RULE_ACTION_PROXY, TRUE);

        UINT8 out_app[16] = {0};
        UINT16 out_port = 0;
        BOOL exact = FALSE;

        CHECK(resolve_udp_response(AF_INET, srvA, srv_port, out_app, &out_port, &exact) == TRUE,
              "exact responder resolves");
        CHECK(exact == TRUE, "exact flag set");
        CHECK(memcmp(out_app, app, 4) == 0, "delivers to the app address");
        CHECK(out_port == app_port, "delivers to the app port");

        memset(out_app, 0, sizeof(out_app)); out_port = 0; exact = TRUE;
        CHECK(resolve_udp_response(AF_INET, srvB, srv_port, out_app, &out_port, &exact) == TRUE,
              "same port, different responder address still resolves");
        CHECK(exact == FALSE, "exact flag cleared for the port-only fallback");
        CHECK(memcmp(out_app, app, 4) == 0, "port-only match still targets the app");
        CHECK(out_port == app_port, "port-only match keeps the app port");

        CHECK(resolve_udp_response(AF_INET6, srvA, srv_port, out_app, &out_port, &exact) == FALSE,
              "family mismatch -> miss");
        CHECK(resolve_udp_response(AF_INET, srvA, 1234, out_app, &out_port, &exact) == FALSE,
              "unknown port -> miss");

        clear_connections();
        CHECK(resolve_udp_response(AF_INET, srvA, srv_port, out_app, &out_port, &exact) == FALSE,
              "cleared -> miss");
    }

    return test_summary("test_udp_rewrite");
}
