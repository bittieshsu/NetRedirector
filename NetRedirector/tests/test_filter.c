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

// IPv6 packet builder: 40-byte IPv6 header + a real L4 header.
//
// The L4 header must actually be long enough for its type: the WinDivert parser
// uses the IPv6 payload length to bound the header, so a TCP packet declared as
// 8 bytes of payload parses as "no TCP header at all" and every tcp.* test
// silently evaluates false. (Cost me one red test.)
static UINT make_packet6(unsigned char *buf, BOOL tcp,
                         const char *src, UINT16 sport,
                         const char *dst, UINT16 dport)
{
    UINT payload = tcp ? 20 : 8;
    memset(buf, 0, 40 + payload);
    PWINDIVERT_IPV6HDR ip6 = (PWINDIVERT_IPV6HDR)buf;
    ip6->Version = 6;
    ip6->Length = htons((UINT16)payload);
    ip6->NextHdr = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    ip6->HopLimit = 64;
    // SrcAddr/DstAddr are UINT32[4]; inet_pton writes the 16 raw bytes.
    if (inet_pton(AF_INET6, src, ip6->SrcAddr) != 1) return 0;
    if (inet_pton(AF_INET6, dst, ip6->DstAddr) != 1) return 0;

    // TCP and UDP both carry SrcPort/DstPort at offset 0/2 of the L4 header, so
    // one writer covers both; TCP additionally needs a data offset of 5.
    unsigned char *l4 = buf + 40;
    *(UINT16 *)(l4 + 0) = htons(sport);
    *(UINT16 *)(l4 + 2) = htons(dport);
    if (tcp) ((PWINDIVERT_TCPHDR)l4)->HdrLength = 5;
    else     ((PWINDIVERT_UDPHDR)l4)->Length = htons(8);

    return 40 + payload;
}

static BOOL eval_filter6(const char *filter, BOOL tcp, BOOL outbound,
                         const char *src, UINT16 sport, const char *dst, UINT16 dport)
{
    unsigned char pkt[64];
    UINT len = make_packet6(pkt, tcp, src, sport, dst, dport);
    if (len == 0) return FALSE;
    WINDIVERT_ADDRESS addr;
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = outbound;
    addr.IPv6 = 1;
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

    printf("\n== 6. DHCPv6 is excluded by the IPv6 UDP clause (it used to be captured) ==\n");
    // The v6 clause used to carry 67/68 - the IPv4 DHCP ports - copied from the
    // v4 branch. IPv6 has no DHCPv4: DHCPv6 is client 546 / server 547. Leaving
    // 546/547 unexcluded meant every renewal was captured and paid a full
    // user-mode round trip. Never a correctness bug (the rule engine forces
    // multicast/link-local IPv6 to DIRECT), but pure waste. Pinned here so the
    // copy-paste cannot come back.
    CHECK(strstr(filter, "udp.DstPort != 546") != NULL, "v6 clause excludes DHCPv6 client port 546");
    CHECK(strstr(filter, "udp.SrcPort != 547") != NULL, "v6 clause excludes DHCPv6 server port 547");

    // The shipped filter, on real DHCPv6 packets.
    CHECK(!eval_filter6(filter, 0, 1, "fe80::1", 546, "ff02::1:2", 547),
          "outbound DHCPv6 Solicit (546 -> 547) -> excluded");
    CHECK(!eval_filter6(filter, 0, 1, "fe80::2", 547, "fe80::1", 546),
          "outbound DHCPv6 Reply (547 -> 546) -> excluded");

    // Isolated old-vs-new, on the same packet. This is what makes the two
    // assertions above meaningful: it shows the behaviour actually CHANGED,
    // rather than pinning a value that already happened to hold.
    {
        // Frozen historical strings. Deliberately NOT derived from the source -
        // they are the reference point the change is measured against.
        static const char *OLD_V6 =
            "(ipv6 and udp and outbound and udp.SrcPort != 67 and udp.DstPort != 67"
            " and udp.SrcPort != 68 and udp.DstPort != 68)";
        static const char *NEW_V6 =
            "(ipv6 and udp and outbound and udp.SrcPort != 546 and udp.DstPort != 546"
            " and udp.SrcPort != 547 and udp.DstPort != 547)";
        BOOL old_cap = eval_filter6(OLD_V6, 0, 1, "fe80::1", 546, "ff02::1:2", 547);
        BOOL new_cap = eval_filter6(NEW_V6, 0, 1, "fe80::1", 546, "ff02::1:2", 547);
        CHECK(old_cap && !new_cap, "old clause captured DHCPv6, new clause excludes it (behaviour changed)");

        // Control: the change must be scoped to the DHCPv6 ports and nothing else.
        BOOL old_ctl = eval_filter6(OLD_V6, 0, 1, "2001:db8::1", 12345, "2001:db8::2", 443);
        BOOL new_ctl = eval_filter6(NEW_V6, 0, 1, "2001:db8::1", 12345, "2001:db8::2", 443);
        CHECK(old_ctl && new_ctl, "control packet captured by both old and new clause");
    }

    printf("\n== 7. IPv6 UDP traffic that must stay captured (over-exclusion = IP leak) ==\n");
    CHECK(eval_filter6(filter, 0, 1, "2001:db8::1", 12345, "2001:db8::2", 443),
          "outbound IPv6 UDP (QUIC) -> captured");
    CHECK(!eval_filter6(filter, 0, 1, "2001:db8::1", 12345, "2001:db8::2", 547),
          "outbound IPv6 UDP with dst 547 -> excluded (the exclusion is symmetric on both ports)");
    CHECK(eval_filter6(filter, 0, 0, "2001:db8::2", 53, "2001:db8::1", 12345),
          "inbound IPv6 DNS response (snooping path) -> captured");
    CHECK(eval_filter6(filter, 1, 1, "2001:db8::1", 51000, "2001:db8::2", 443),
          "outbound IPv6 TCP -> captured");
    CHECK(!eval_filter6(filter, 0, 1, "::1", 51000, "::1", 3306),
          "IPv6 loopback -> excluded (pre-existing)");

    return test_summary("test_filter");
}
