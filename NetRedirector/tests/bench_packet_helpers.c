// Microbenchmark: per-packet CPU cost of the WinDivert helper calls that
// process_packet() makes for every captured packet.
//
// Purpose: decide whether further packet-path optimisation can raise the
// throughput ceiling at all, or whether the ceiling is the network path. The
// helpers are pure user-mode functions in WinDivert.dll, so this needs neither
// the driver nor admin rights.
//
// Build & run (from NetRedirector\):
//   C:\ProgramData\mingw64\mingw64\bin\gcc -O2 -o tests\bench_packet_helpers.exe ^
//       tests\bench_packet_helpers.c -I. -lws2_32
//   cd .. && NetRedirector\tests\bench_packet_helpers.exe

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"

typedef BOOL (WINAPI *PFN_Parse)(const VOID *, UINT, PWINDIVERT_IPHDR *,
    PWINDIVERT_IPV6HDR *, PWINDIVERT_ICMPHDR *, PWINDIVERT_ICMPV6HDR *,
    PWINDIVERT_TCPHDR *, PWINDIVERT_UDPHDR *, PVOID *, UINT *, PVOID *, UINT *,
    PVOID *, UINT *);
typedef BOOL (WINAPI *PFN_Checksums)(PVOID, UINT, PWINDIVERT_ADDRESS, UINT64);

#define ITERATIONS 2000000
#define PACKET_LEN 1500

// Packets per second at a given Mbps with 1500-byte frames.
static double pps_at(double mbps)
{
    return (mbps * 1000000.0 / 8.0) / PACKET_LEN;
}

static UINT build_v4_tcp(unsigned char *buf, UINT len)
{
    memset(buf, 0, len);
    PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)buf;
    ip->Version = 4;
    ip->HdrLength = 5;
    ip->Length = htons((UINT16)len);
    ip->TTL = 64;
    ip->Protocol = IPPROTO_TCP;
    ip->SrcAddr = inet_addr("192.168.1.10");
    ip->DstAddr = inet_addr("1.1.1.1");
    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(buf + 20);
    tcp->SrcPort = htons(51000);
    tcp->DstPort = htons(443);
    tcp->HdrLength = 5;
    tcp->Window = htons(65535);
    return len;
}

static UINT build_v6_tcp(unsigned char *buf, UINT len)
{
    memset(buf, 0, len);
    PWINDIVERT_IPV6HDR ip6 = (PWINDIVERT_IPV6HDR)buf;
    ip6->Version = 6;
    ip6->Length = htons((UINT16)(len - 40));
    ip6->NextHdr = IPPROTO_TCP;
    ip6->HopLimit = 64;
    ip6->SrcAddr[0] = 0xfe; ip6->SrcAddr[1] = 0x80;
    ip6->DstAddr[15] = 0x01;
    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(buf + 40);
    tcp->SrcPort = htons(51000);
    tcp->DstPort = htons(443);
    tcp->HdrLength = 5;
    return len;
}

static double time_ns(LARGE_INTEGER t0, LARGE_INTEGER t1, double freq)
{
    return ((double)(t1.QuadPart - t0.QuadPart) * 1e9) / freq / ITERATIONS;
}

int main(void)
{
    HMODULE dll = LoadLibraryA("WinDivert.dll");
    if (dll == NULL) { printf("FATAL: cannot load WinDivert.dll\n"); return 2; }
    PFN_Parse parse = (PFN_Parse)(void*)GetProcAddress(dll, "WinDivertHelperParsePacket");
    PFN_Checksums cksum = (PFN_Checksums)(void*)GetProcAddress(dll, "WinDivertHelperCalcChecksums");
    if (!parse || !cksum) { printf("FATAL: helper exports not found\n"); return 2; }

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    unsigned char v4[PACKET_LEN], v6[PACKET_LEN];
    build_v4_tcp(v4, PACKET_LEN);
    build_v6_tcp(v6, PACKET_LEN);

    WINDIVERT_ADDRESS addr;
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = 1;
    addr.Layer = WINDIVERT_LAYER_NETWORK;

    volatile int sink = 0;
    PWINDIVERT_IPHDR ip; PWINDIVERT_IPV6HDR ip6;
    PWINDIVERT_ICMPHDR icmp; PWINDIVERT_ICMPV6HDR icmp6;
    PWINDIVERT_TCPHDR tcp; PWINDIVERT_UDPHDR udp;
    PVOID p1, p2, p3; UINT l1, l2, l3;

    printf("WinDivert helper microbenchmark  (%d iterations, %d-byte frames)\n\n",
           ITERATIONS, PACKET_LEN);

    // Warm up
    for (int i = 0; i < 10000; i++) {
        parse(v4, PACKET_LEN, &ip, &ip6, &icmp, &icmp6, &tcp, &udp, &p1, &l1, &p2, &l2, &p3, &l3);
        cksum(v4, PACKET_LEN, &addr, 0);
    }

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < ITERATIONS; i++) {
        parse(v4, PACKET_LEN, &ip, &ip6, &icmp, &icmp6, &tcp, &udp, &p1, &l1, &p2, &l2, &p3, &l3);
        sink += (ip != NULL) + (tcp != NULL) + (UINT)(uintptr_t)p1;
    }
    QueryPerformanceCounter(&t1);
    double ns_parse4 = time_ns(t0, t1, (double)freq.QuadPart);

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < ITERATIONS; i++) {
        parse(v6, PACKET_LEN, &ip, &ip6, &icmp, &icmp6, &tcp, &udp, &p1, &l1, &p2, &l2, &p3, &l3);
        sink += (ip6 != NULL) + (tcp != NULL) + (UINT)(uintptr_t)p1;
    }
    QueryPerformanceCounter(&t1);
    double ns_parse6 = time_ns(t0, t1, (double)freq.QuadPart);

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < ITERATIONS; i++) {
        cksum(v4, PACKET_LEN, &addr, 0);
        sink++;
    }
    QueryPerformanceCounter(&t1);
    double ns_cksum4 = time_ns(t0, t1, (double)freq.QuadPart);

    printf("  WinDivertHelperParsePacket  (IPv4/TCP) : %8.1f ns/op\n", ns_parse4);
    printf("  WinDivertHelperParsePacket  (IPv6/TCP) : %8.1f ns/op\n", ns_parse6);
    printf("  WinDivertHelperCalcChecksums(IPv4/TCP) : %8.1f ns/op\n", ns_cksum4);
    printf("  (sink=%d)\n\n", sink);

    printf("Per-packet CPU in the relay's process_packet(), and what it costs\n");
    printf("as a fraction of ONE core at various single-flow rates:\n\n");
    printf("  %-14s %10s %10s %10s %10s\n", "throughput", "pps", "1x parse", "2x parse", "+cksum");
    const double rates[] = { 100, 280, 500, 1000 };
    for (int i = 0; i < 4; i++) {
        double pps = pps_at(rates[i]);
        double one = ns_parse4 * pps / 1e7;           // percent of one core
        double two = 2.0 * one;
        double with_cksum = two + ns_cksum4 * pps / 1e7;
        printf("  %6.0f Mbps %10.0f %9.2f%% %9.2f%% %9.2f%%\n",
               rates[i], pps, one, two, with_cksum);
    }
    printf("\n  (percentages assume a single core; the relay has %d packet threads\n"
           "   and the receiver is the serial point.)\n", 4);
    return 0;
}
