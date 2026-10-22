import socket
import struct
import argparse
import os
import threading

DEFAULT_PORT = 22
DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 5

SSH_MSG_KEXINIT = 20
VULNERABLE_CIPHERS = {"chacha20-poly1305@openssh.com"}
CBC_CIPHER_SUFFIX = "-cbc"
ETM_MAC_SUFFIX = "-etm@openssh.com"
STRICT_KEX_MARKERS = {"kex-strict-s-v00@openssh.com", "kex-strict-c-v00@openssh.com"}

NAME_LIST_FIELDS = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
]


def recv_exact(sock, n):
    """Read exactly n bytes or raise if the connection closes early."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed before expected data arrived")
        data += chunk
    return data


def read_identification_string(sock):
    """Read the SSH-2.0-... banner line (RFC 4253 4.2); skip any preceding lines."""
    for _ in range(50):
        line = b""
        while not line.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("connection closed while reading banner")
            line += b
        if line.startswith(b"SSH-"):
            return line.strip().decode(errors="replace")
    raise ConnectionError("no SSH identification string received")


def read_kexinit_payload(sock):
    """Read binary packets until SSH_MSG_KEXINIT is found; return its payload."""
    for _ in range(10):
        length_bytes = recv_exact(sock, 4)
        packet_length = struct.unpack(">I", length_bytes)[0]
        if not (0 < packet_length <= 262144):
            raise ValueError(f"implausible SSH packet length: {packet_length}")
        rest = recv_exact(sock, packet_length)
        padding_length = rest[0]
        payload = rest[1:packet_length - padding_length]
        if payload and payload[0] == SSH_MSG_KEXINIT:
            return payload
    raise ValueError("did not receive KEXINIT within expected number of packets")


def parse_name_lists(payload):
    """Parse the 10 ordered name-lists out of a KEXINIT payload (RFC 4253 7.1)."""
    offset = 1 + 16  # msg type byte + 16-byte cookie
    fields = []
    for _ in range(10):
        (list_len,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        raw = payload[offset:offset + list_len]
        offset += list_len
        fields.append(raw.decode(errors="replace").split(",") if raw else [])
    return dict(zip(NAME_LIST_FIELDS, fields))


def assess_terrapin(algos):
    enc_s2c = set(algos["encryption_server_to_client"])
    mac_s2c = set(algos["mac_server_to_client"])
    kex = set(algos["kex_algorithms"])

    offers_chacha = bool(enc_s2c & VULNERABLE_CIPHERS)
    offers_cbc = any(c.endswith(CBC_CIPHER_SUFFIX) for c in enc_s2c)
    offers_etm = any(m.endswith(ETM_MAC_SUFFIX) for m in mac_s2c)
    offers_vulnerable_combo = offers_chacha or (offers_cbc and offers_etm)

    strict_kex = bool(kex & STRICT_KEX_MARKERS)
    vulnerable = offers_vulnerable_combo and not strict_kex

    return {
        "vulnerable": vulnerable,
        "offers_chacha20_poly1305": offers_chacha,
        "offers_cbc_etm_combo": bool(offers_cbc and offers_etm),
        "strict_kex_supported": strict_kex,
    }


def check_host(ip, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = read_identification_string(sock)
            # Some implementations wait for the client's ID string before
            # sending KEXINIT; sending ours doesn't hurt if they don't.
            sock.sendall(b"SSH-2.0-TerrapinCheck_1.0\r\n")
            payload = read_kexinit_payload(sock)
            algos = parse_name_lists(payload)
            assessment = assess_terrapin(algos)

            result = {"ip": ip, "port": port, "banner": banner, **assessment}

            if assessment["vulnerable"]:
                print(f"[Vulnerable]\n{ip} - {banner}\n")
            else:
                print(f"[Safe]\n{ip} - {banner}\n")
            return result
    except Exception as e:
        print(f"[Error]\n{ip} - {e}\n")
        return {"ip": ip, "port": port, "error": str(e)}


def process_ips(ips, port=DEFAULT_PORT, threads=DEFAULT_THREADS):
    semaphore = threading.Semaphore(threads)

    def worker(ip):
        with semaphore:
            check_host(ip, port)

    thread_list = [threading.Thread(target=worker, args=(ip,)) for ip in ips]
    for t in thread_list:
        t.start()
    for t in thread_list:
        t.join()


def main():
    parser = argparse.ArgumentParser(description="Terrapin (CVE-2023-48795) SSH vulnerability scanner")
    parser.add_argument("-ip", type=str, required=True,
                         help="Single IP/hostname, or path to a file containing one per line")
    parser.add_argument("-port", type=int, default=DEFAULT_PORT,
                         help=f"SSH port (default: {DEFAULT_PORT})")
    args = parser.parse_args()

    if os.path.isfile(args.ip):
        with open(args.ip, "r") as f:
            ips = [line.strip() for line in f if line.strip()]
    else:
        ips = [args.ip]

    process_ips(ips, args.port)


if __name__ == "__main__":
    main()
