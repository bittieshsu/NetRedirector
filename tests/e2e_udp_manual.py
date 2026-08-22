# -*- coding: utf-8 -*-
"""端到端 UDP 代理鏈路測試:
本機起一個最小 SOCKS5 伺服器 (TCP CONNECT + UDP ASSOCIATE),
驅動 NetRedirector.dll 攔截 nslookup.exe 的流量走該代理,
驗證 DNS 查詢全程 (app -> NAT -> relay -> SOCKS5 -> 真實 DNS -> 回程還原)。

用法 (需管理員): python tests/e2e_udp_test.py
"""
import ctypes
import os
import socket
import struct
import subprocess
import sys
import threading
import select
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SOCKS_PORT = 11080
DLL_LOGS = []


# ---------------- 最小 SOCKS5 伺服器 ----------------

def socks5_tcp_session(conn):
    """處理一條 SOCKS5 TCP 連線 (CONNECT 或 UDP ASSOCIATE)。"""
    try:
        hdr = recvn(conn, 2)
        nmethods = hdr[1]
        recvn(conn, nmethods)
        conn.sendall(b"\x05\x00")  # no-auth

        req = recvn(conn, 4)
        ver, cmd, rsv, atyp = req
        if atyp == 1:
            addr = socket.inet_ntoa(recvn(conn, 4))
        elif atyp == 3:
            ln = recvn(conn, 1)[0]
            addr = recvn(conn, ln).decode()
        elif atyp == 4:
            addr = socket.inet_ntop(socket.AF_INET6, recvn(conn, 16))
        else:
            conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = struct.unpack("!H", recvn(conn, 2))[0]

        if cmd == 0x01:  # CONNECT
            remote = socket.create_connection((addr, port), timeout=10)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay_tcp(conn, remote)
        elif cmd == 0x03:  # UDP ASSOCIATE
            # [Fixed] 必須綁 0.0.0.0: 這個 socket 除了收客戶端封包,
            # 還要對真實目的地 (8.8.8.8 等) 收發 — 綁 127.0.0.1 會讓對外
            # sendto 直接拋例外 (本機客戶端仍可經 127.0.0.1 連入)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("0.0.0.0", 0))
            udp_port = udp.getsockname()[1]
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_port))
            socks5_udp_relay(udp, conn)
            udp.close()
        else:
            conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def socks5_udp_relay(udp, control):
    """UDP ASSOCIATE 資料面:拆封客戶端 SOCKS5 封包轉發;回程再包回去。"""
    client_ep = None
    while True:
        r, _, _ = select.select([udp, control], [], [], 10)
        if not r:
            break
        if control in r:
            if recvn_nb(control) == b"":   # control 斷開 -> 結束
                break
        if udp in r:
            data, ep = udp.recvfrom(65535)
            client_ep = ep
            if len(data) < 10:
                continue
            # SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) ADDR PORT
            atyp = data[3]
            if atyp == 1:
                dest = socket.inet_ntoa(data[4:8])
                dport = struct.unpack("!H", data[8:10])[0]
                payload = data[10:]
            else:
                continue
            udp.sendto(payload, (dest, dport))
            # 等回應 (最多 3 秒) 再包裝送回
            rr, _, _ = select.select([udp], [], [], 3)
            if rr:
                resp, src = udp.recvfrom(65535)
                wrapped = b"\x00\x00\x00\x01" + socket.inet_aton(src[0]) + struct.pack("!H", src[1]) + resp
                udp.sendto(wrapped, ep)


def relay_tcp(a, b):
    while True:
        r, _, _ = select.select([a, b], [], [], 30)
        if not r:
            break
        try:
            if a in r:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
            if b in r:
                d = b.recv(65536)
                if not d:
                    break
                a.sendall(d)
        except Exception:
            break


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise ConnectionError("short read")
        buf += d
    return buf


def recvn_nb(s):
    try:
        s.setblocking(False)
        try:
            return s.recv(1)
        finally:
            s.setblocking(True)
    except Exception:
        return b"x"


def start_socks5_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", SOCKS_PORT))
    srv.listen(16)
    def accept_loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=socks5_tcp_session, args=(c,), daemon=True).start()
    threading.Thread(target=accept_loop, daemon=True).start()
    return srv


# ---------------- DLL 驅動 ----------------

def run_test():
    dll_path = sys.argv[1] if len(sys.argv) > 1 else "NetRedirector.dll"
    dll_path = os.path.abspath(dll_path)
    print(f"[dll] using {dll_path}")
    if os.path.dirname(dll_path) != os.getcwd():
        os.add_dll_directory(os.path.dirname(dll_path))   # 讓 WinDivert.dll 等相依從同目錄解析

    # 0. 基線: 不經攔截的 DNS 查詢
    baseline = subprocess.run(
        ["nslookup", "-timeout=4", "example.com", "8.8.8.8"],
        capture_output=True, timeout=20, encoding="cp950", errors="replace")
    print(f"[baseline] returncode={baseline.returncode}")
    print("  stdout:", (baseline.stdout or "").strip().replace("\n", " | ")[:160])

    srv = start_socks5_server()
    print(f"[socks5] listening on 127.0.0.1:{SOCKS_PORT}")

    lib = ctypes.CDLL(dll_path)
    LOG_CB = ctypes.CFUNCTYPE(None, ctypes.c_char_p)

    def on_log(msg):
        try:
            DLL_LOGS.append(msg.decode("utf-8", "ignore"))
        except Exception:
            pass

    log_cb = LOG_CB(on_log)
    lib.NetRedirector_SetLogCallback.argtypes = [LOG_CB]
    lib.NetRedirector_SetLogCallback(log_cb)

    lib.NetRedirector_AddProxyConfig.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                                                 ctypes.c_uint16, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_bool]
    lib.NetRedirector_AddProxyConfig.restype = ctypes.c_uint32
    proxy_id = lib.NetRedirector_AddProxyConfig(1, b"TestSocks", b"127.0.0.1", SOCKS_PORT, b"", b"", True)
    print(f"[dll] proxy_id={proxy_id}")

    lib.NetRedirector_AddRuleWithProxy.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                                   ctypes.c_int, ctypes.c_int, ctypes.c_uint32]
    lib.NetRedirector_AddRuleWithProxy.restype = ctypes.c_uint32
    rid = lib.NetRedirector_AddRuleWithProxy(b"nslookup.exe", b"*", b"*", 2, 0, proxy_id)
    print(f"[dll] rule_id={rid}")

    lib.NetRedirector_Start.restype = ctypes.c_bool
    lib.NetRedirector_Stop.restype = ctypes.c_bool

    ok = lib.NetRedirector_Start()
    print(f"[dll] Start()={ok}")
    if not ok:
        return 2

    try:
        time.sleep(0.5)
        try:
            result = subprocess.run(
                ["nslookup", "-timeout=5", "example.com", "8.8.8.8"],
                capture_output=True, timeout=25, encoding="cp950", errors="replace")
            print(f"[proxied] returncode={result.returncode}")
            print("  stdout:", (result.stdout or "").strip().replace("\n", " | ")[:200])
            print("  stderr:", (result.stderr or "").strip().replace("\n", " | ")[:200])
            rc = 0 if result.returncode == 0 else 1
        except subprocess.TimeoutExpired:
            print("[proxied] TIMEOUT — 查詢未完成 (鏈路中斷)")
            rc = 1
    finally:
        lib.NetRedirector_Stop()
        print("[dll] stopped")

    srv.close()
    print("---- DLL log (最後 25 條) ----")
    for line in DLL_LOGS[-25:]:
        print("  ", line)
    return rc


if __name__ == "__main__":
    sys.exit(run_test())
