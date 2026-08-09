// --- START OF FILE NR_Protocol.h ---
#ifndef NR_PROTOCOL_H
#define NR_PROTOCOL_H

#include "NR_Common.h"
#include "NR_Utils.h"

// SOCKS5 Protocol Constants
#define SOCKS5_VERSION 0x05
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_IPV6 0x04
#define SOCKS5_AUTH_NONE 0x00

// Protocol Implementations
int socks5_connect_with_config(SOCKET s, int family, const UINT8 *dest_addr, UINT16 dest_port, const PROXY_CONFIG* proxy_config);
int http_connect_with_config(SOCKET s, int family, const UINT8 *dest_addr, UINT16 dest_port, const PROXY_CONFIG* proxy_config);
int socks5_udp_associate_with_config(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG* proxy_config);
UDP_ASSOCIATION* establish_udp_associate_with_config(const PROXY_CONFIG* proxy_config);

#endif // NR_PROTOCOL_H