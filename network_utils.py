
import socket
import struct
import time
import ctypes
from ctypes import Structure, POINTER, c_void_p, c_char_p, c_wchar_p, c_ulong, c_ushort, c_ubyte, c_uint, c_int, byref, sizeof, cast

# ==========================================
# Windows API 定義 (IP Helper API & Winsock)
# ==========================================

# 預設 Ping 目標（可透過 config.json 的 "ping_target" 覆寫）
PING_TARGET = "8.8.8.8"

try:
    iphlpapi = ctypes.windll.iphlpapi
    ws2_32 = ctypes.windll.ws2_32

    # === [關鍵修正] 明確定義函數原型以支援 64-bit ===
    
    # IcmpCreateFile
    iphlpapi.IcmpCreateFile.argtypes = []
    iphlpapi.IcmpCreateFile.restype = c_void_p  # 64-bit Handle

    # IcmpCloseHandle
    iphlpapi.IcmpCloseHandle.argtypes = [c_void_p]
    iphlpapi.IcmpCloseHandle.restype = c_int

    # IcmpSendEcho
    # DWORD IcmpSendEcho(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
    iphlpapi.IcmpSendEcho.argtypes = [
        c_void_p, c_ulong, c_void_p, c_ushort, 
        c_void_p, c_void_p, c_ulong, c_ulong
    ]
    iphlpapi.IcmpSendEcho.restype = c_ulong

    # GetAdaptersAddresses
    iphlpapi.GetAdaptersAddresses.argtypes = [
        c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong)
    ]
    iphlpapi.GetAdaptersAddresses.restype = c_ulong
    
    # inet_addr
    ws2_32.inet_addr.argtypes = [c_char_p]
    ws2_32.inet_addr.restype = c_ulong

except AttributeError:
    iphlpapi = None
    ws2_32 = None

# --- 常數定義 ---
AF_INET = 2
AF_INET6 = 23  # Windows 上的 AF_INET6 值
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
ERROR_BUFFER_OVERFLOW = 111
IF_OPER_STATUS_UP = 1
INVALID_HANDLE_VALUE = c_void_p(-1).value

# --- 結構體定義 ---

class sockaddr(Structure):
    _fields_ = [
        ("sa_family", c_ushort),
        ("sa_data", c_ubyte * 14)
    ]

class SOCKET_ADDRESS(Structure):
    _fields_ = [
        ("lpSockaddr", POINTER(sockaddr)),
        ("iSockaddrLength", c_int)
    ]

class IP_ADAPTER_UNICAST_ADDRESS(Structure):
    pass
IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", c_ulong),
    ("Flags", c_ulong),
    ("Next", POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", c_uint),
    ("SuffixOrigin", c_uint),
    ("DadState", c_uint),
    ("ValidLifetime", c_ulong),
    ("PreferredLifetime", c_ulong),
    ("LeaseLifetime", c_ulong),
    ("OnLinkPrefixLength", c_ubyte)
]

class IP_ADAPTER_ADDRESSES(Structure):
    pass
IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", c_ulong),
    ("IfIndex", c_ulong),
    ("Next", POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", c_char_p),
    ("FirstUnicastAddress", POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", c_void_p),
    ("FirstMulticastAddress", c_void_p),
    ("FirstDnsServerAddress", c_void_p),
    ("DnsSuffix", c_wchar_p),
    ("Description", c_wchar_p),
    ("FriendlyName", c_wchar_p),
    ("PhysicalAddress", c_ubyte * 8),
    ("PhysicalAddressLength", c_ulong),
    ("Flags", c_ulong),
    ("Mtu", c_ulong),
    ("IfType", c_ulong),
    ("OperStatus", c_uint),
]

class IP_OPTION_INFORMATION(Structure):
    _fields_ = [
        ("Ttl", c_ubyte), ("Tos", c_ubyte), ("Flags", c_ubyte),
        ("OptionsSize", c_ubyte), ("OptionsData", c_void_p)
    ]

class ICMP_ECHO_REPLY(Structure):
    _fields_ = [
        ("Address", c_ulong), ("Status", c_ulong), ("RoundTripTime", c_ulong),
        ("DataSize", c_ushort), ("Reserved", c_ushort), ("Data", c_void_p),
        ("Options", IP_OPTION_INFORMATION)
    ]

# ==========================================
# 核心功能函式
# ==========================================

def get_system_interfaces():
    interfaces = {}
    if not iphlpapi: return interfaces

    size = c_ulong(15000)
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    
    # 第一次呼叫 (獲取大小)
    ret = iphlpapi.GetAdaptersAddresses(AF_INET, flags, None, None, byref(size))
    if ret != ERROR_BUFFER_OVERFLOW and ret != 0: return interfaces

    # 第二次呼叫 (獲取資料)
    buffer = ctypes.create_string_buffer(size.value)
    ret = iphlpapi.GetAdaptersAddresses(AF_INET, flags, None, buffer, byref(size))
    if ret != 0: return interfaces

    p_adapter = cast(buffer, POINTER(IP_ADAPTER_ADDRESSES))
    
    while p_adapter:
        try:
            adapter = p_adapter.contents
            name = adapter.FriendlyName
            desc = adapter.Description
            
            if "Loopback" in desc or "Pseudo" in desc:
                p_adapter = adapter.Next
                continue

            ipv4 = None
            ipv6 = None
            p_unicast = adapter.FirstUnicastAddress
            
            while p_unicast:
                unicast = p_unicast.contents
                sockaddr_ptr = unicast.Address.lpSockaddr
                
                if sockaddr_ptr and sockaddr_ptr.contents.sa_family == AF_INET:
                    addr_ptr = cast(ctypes.addressof(sockaddr_ptr.contents) + 4, POINTER(c_ubyte * 4))
                    ip_bytes = addr_ptr.contents
                    ip_str = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
                    
                    if not ip_str.startswith("169.254"):
                        ipv4 = ip_str
                        break
                elif sockaddr_ptr and sockaddr_ptr.contents.sa_family == AF_INET6:
                    # [新增] 同時收集 IPv6 位址 (sin6_addr 位於 sockaddr_in6 結構偏移 8)
                    addr_ptr = cast(ctypes.addressof(sockaddr_ptr.contents) + 8, POINTER(c_ubyte * 16))
                    try:
                        ipv6_str = socket.inet_ntop(socket.AF_INET6, bytes(addr_ptr.contents))
                    except OSError:
                        ipv6_str = None
                    # 跳過 fe80:: link-local；其餘 (全域/ULA/Teredo 等) 保留
                    if ipv6_str and not ipv6_str.startswith("fe80::"):
                        ipv6 = ipv6_str
                        
                p_unicast = unicast.Next

            if ipv4:
                interfaces[name] = {
                    'ipv4': ipv4,
                    'ipv6': ipv6,
                    'connected': (adapter.OperStatus == IF_OPER_STATUS_UP),
                    'is_vpn': check_is_vpn(name) or check_is_vpn(desc)
                }

        except Exception:
            pass
        p_adapter = adapter.Next

    return interfaces

def check_is_vpn(name):
    if not name: return False
    name_lower = name.lower()
    vpn_patterns = [
        'vpn', 'tun', 'tap', 'wireguard', 'pptp', 'l2tp', 
        'express', 'nord', 'tailscale', 'zerotier', 'openvpn', 
        'fortinet', 'globalprotect', 'anyconnect', 'radmin'
    ]
    return any(p in name_lower for p in vpn_patterns)

def ping_address(source_ip, target=PING_TARGET, timeout_ms=500):
    if not iphlpapi or not ws2_32:
        return tcp_ping(target, 80, timeout_ms)

    icmp_handle = None
    try:
        try:
            if not target.replace('.', '').isdigit():
                target = socket.gethostbyname(target)
            dest_addr = ws2_32.inet_addr(target.encode('ascii'))
        except:
            return 9999

        if dest_addr == 0xFFFFFFFF: return 9999

        # 這裡會因為上面定義了 restype=c_void_p 而返回正確的 64-bit Handle
        icmp_handle = iphlpapi.IcmpCreateFile()
        
        # 檢查 Handle 是否有效 (注意 INVALID_HANDLE_VALUE 是 -1)
        if not icmp_handle or icmp_handle == INVALID_HANDLE_VALUE:
            return 9999

        send_data = b'PingCheck'
        reply_size = sizeof(ICMP_ECHO_REPLY) + len(send_data) + 8
        reply_buffer = ctypes.create_string_buffer(reply_size)

        ret = iphlpapi.IcmpSendEcho(
            icmp_handle,
            dest_addr,
            send_data,
            len(send_data),
            None,
            reply_buffer,
            reply_size,
            timeout_ms
        )

        if ret > 0:
            reply = cast(reply_buffer, POINTER(ICMP_ECHO_REPLY)).contents
            if reply.Status == 0:
                return reply.RoundTripTime
            else:
                return 9999
        else:
            return 9999

    except Exception:
        return 9999
    finally:
        # [修正] 只有當 Handle 有效且不為 -1 時才關閉
        if icmp_handle and icmp_handle != INVALID_HANDLE_VALUE:
            try:
                iphlpapi.IcmpCloseHandle(icmp_handle)
            except OSError:
                pass # 防止已經關閉或無效時的二次崩潰

def tcp_ping(host, port=80, timeout_ms=500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_ms / 1000.0)
        start = time.time()
        s.connect((host, port))
        end = time.time()
        s.close()
        return int((end - start) * 1000)
    except:
        return 9999

if __name__ == "__main__":
    print("正在掃描介面 (Native API)...")
    ifaces = get_system_interfaces()
    for k, v in ifaces.items():
        print(f"介面: {k}, IP: {v['ipv4']}, VPN: {v['is_vpn']}, 連線中: {v['connected']}")
        latency = ping_address(v['ipv4'], "8.8.8.8")
        print(f"  -> Ping 8.8.8.8: {latency} ms")