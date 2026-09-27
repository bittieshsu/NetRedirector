// --- TEST: WinDivert filter construction (build_windivert_filter) ---
//
// The filter has two hand-written De Morgan exclusion clauses (the WinDivert
// filter language has no unary NOT). An over-broad exclusion silently stops
// proxying a whole class of traffic - which leaks the real IP; an over-narrow
// one just wastes a user-mode round trip. Neither shows up as a crash, so the
// semantics are pinned here.
//
// WinDivertHelperCompileFilter / WinDivertHelperEvalFilter are pure user-mode
// functions: no driver, no admin rights needed.
//
// Note on reachability: NetRedirector_AddProxyConfig and _SetProxyConfig both
// validate through resolve_hostname(), which is IPv4-only (ai_family = AF_INET).
// So an IPv6 endpoint cannot currently be configured through either API, and a
// resolvable HOSTNAME is stored verbatim as-is. The IPv6 branch is therefore
// exercised by writing the legacy globals directly, and the hostname case is
// covered through the normal API.

#include "test_framework.h"
#include "NR_Common.h"
#include "NetRedirector.h"
#include "windivert.h"

// Provided by NetRedirector.c (non-static precisely so this test can drive the
// real construction path instead of a copy of the format string).
void build_windivert_filter(char *filter, size_t filter_size);

#define RELAY_PORT     33100
#define UDPRELAY_PORT  33200
#define PROXY_IP       "192.168.1.178"
#define PROXY_PORT     1080
#define PROXY_IP6      "2001:db8::1"

static UINT make_packet(unsigned char *buf, BOOL tcp,
                        const char *src, UINT16 sport,
                        const char *dst, UINT16 dport)
{
    memset(buf, 0, 40);
    PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)buf;
    ip->Version = 4;
    ip->HdrLength = 5;
    ip->Length = htons(40);
    ip->TTL = 64;
    ip->Protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    ip->SrcAddr = inet_addr(src);
    ip->DstAddr = inet_addr(dst);
    PWINDIVERT_TCPHDR l4 = (PWINDIVERT_TCPHDR)(buf + 20);
    l4->SrcPort = htons(sport);
    l4->DstPort = htons(dport);
    if (tcp) l4->HdrLength = 5;
    return 40;
}

static BOOL eval_filter(const char *filter, BOOL tcp, BOOL outbound,
                        const char *src, UINT16 sport, const char *dst, UINT16 dport)
{
    unsigned char pkt[64];
    UINT len = make_packet(pkt, tcp, src, sport, dst, dport);
    WINDIVERT_ADDRESS addr;
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = outbound;
    addr.IPv6 = 0;
    addr.Layer = WINDIVERT_LAYER_NETWORK;
    return WinDivertHelperEvalFilter(filter, pkt, len, &addr);
}

int main(void)
{
    init_locks();
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }

    printf("== 0. configure proxy endpoints ==\n");
    UINT32 id4 = NetRedirector_AddProxyConfig(PROXY_TYPE_SOCKS5, "Phone",
                    PROXY_IP, PROXY_PORT, "", "", TRUE);
    CHECK(id4 != 0, "IPv4 endpoint accepted by the API");
    // Resolvable hostname: the API stores the raw string, and the filter must
    // refuse to embed it (the filter language has no DNS).
    UINT32 idh = NetRedirector_AddProxyConfig(PROXY_TYPE_SOCKS5, "ByName",
                    "localhost", PROXY_PORT, "", "", TRUE);
    CHECK(idh != 0, "resolvable hostname accepted by the API");
    // IPv6 endpoints are rejected upstream (resolve_hostname is IPv4-only), so
    // drive the legacy globals directly to cover that branch of the builder.
    strncpy(g_proxy_ip, PROXY_IP6, sizeof(g_proxy_ip) - 1);
    g_proxy_ip[sizeof(g_proxy_ip) - 1] = '\0';
    g_proxy_port = PROXY_PORT;

    char filter[4096];
    build_windivert_filter(filter, sizeof(filter));
    CHECK(filter[0] != '\0', "filter is non-empty");

    printf("\n== 1. filter must still parse ==\n");
    {
        char object[8192];
        const char *err = NULL;
        UINT errpos = 0;
        BOOL ok = WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK,
                                               object, sizeof(object), &err, &errpos);
        if (!ok) printf("       parse error: %s at position %u\n", err ? err : "?", errpos);
        CHECK(ok, "filter compiles");
    }

    printf("\n== 2. exclusion clauses are generated correctly ==\n");
    CHECK(strstr(filter, "ip.DstAddr != " PROXY_IP) != NULL, "IPv4 exclusion clause present");
    CHECK(strstr(filter, "ipv6.SrcAddr != " PROXY_IP6) != NULL, "IPv6 exclusion clause present");
    CHECK(strstr(filter, "localhost") == NULL, "hostname endpoint NOT embedded");
    CHECK(strstr(filter, "tcp.DstPort != 1080") != NULL, "exclusion matches on the port too");
    CHECK(strstr(filter, "udp.DstPort != 1080") != NULL, "UDP exclusion present");

    printf("\n== 3. the relay's own tunnel is excluded (the point of the change) ==\n");
    CHECK(!eval_filter(filter, 1, 1, "192.168.1.10", 51000, PROXY_IP, PROXY_PORT),
          "outbound TCP to proxy endpoint -> excluded");
    CHECK(!eval_filter(filter, 1, 0, PROXY_IP, PROXY_PORT, "192.168.1.10", RELAY_PORT),
          "inbound TCP from proxy endpoint -> excluded");
    CHECK(!eval_filter(filter, 0, 1, "192.168.1.10", 52000, PROXY_IP, PROXY_PORT),
          "outbound UDP to proxy endpoint -> excluded");
    CHECK(!eval_filter(filter, 0, 0, PROXY_IP, PROXY_PORT, "192.168.1.10", UDPRELAY_PORT),
          "inbound UDP from proxy endpoint -> excluded");

    printf("\n== 4. everything else is still captured (over-exclusion = IP leak) ==\n");
    CHECK(eval_filter(filter, 1, 1, "192.168.1.10", 51000, "1.1.1.1", 443),
          "outbound TCP to internet -> captured");
    CHECK(eval_filter(filter, 1, 1, "192.168.1.10", 51000, PROXY_IP, 443),
          "same proxy HOST on another port -> still captured");
    CHECK(eval_filter(filter, 1, 1, "192.168.1.10", 51000, "192.168.1.10", RELAY_PORT),
          "outbound to the relay port -> captured");
    CHECK(eval_filter(filter, 0, 1, "192.168.1.10", 52000, "1.1.1.1", 443),
          "outbound UDP (QUIC) -> captured");
    CHECK(eval_filter(filter, 0, 0, "8.8.8.8", 53, "192.168.1.10", 52000),
          "inbound DNS response (snooping path) -> captured");

    printf("\n== 5. pre-existing exclusions must not regress ==\n");
    CHECK(!eval_filter(filter, 1, 1, "127.0.0.1", 50000, "127.0.0.1", 3306),
          "loopback -> excluded");
    CHECK(!eval_filter(filter, 0, 1, "0.0.0.0", 68, "255.255.255.255", 67),
          "DHCP broadcast -> excluded");
    CHECK(!eval_filter(filter, 1, 0, "1.1.1.1", 443, "192.168.1.10", 51000),
          "inbound TCP to a non-relay port -> excluded (pre-existing)");

    return test_summary("test_filter");
}
