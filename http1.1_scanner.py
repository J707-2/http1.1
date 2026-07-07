#!/usr/bin/env python3

import sys
import ssl
import socket
import os
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

R  = "\033[0m"
B  = "\033[1m"
GR = "\033[32m"
RD = "\033[31m"
YL = "\033[33m"
CY = "\033[36m"
DM = "\033[2m"
MG = "\033[35m"

BANNER = (
    f"{CY}{B}\n"
    "  _     _   _ _   _\n"
    " | |__ | |_| | |_| |__\n"
    r" | '_ \| __| | __| '_ \\" + "\n"
    " | | | | |_| | |_| |_) |\n"
    r" |_| |_\__|_|\__|_.__/" + "\n"
    f"{R}{DM} http/1.1 + keep-alive filter{R}\n"
)

DEFAULT_TIMEOUT = 8
DEFAULT_THREADS = 30
CONFIG_FILE = os.path.expanduser("~/.config/http1.1/config")


def load_output_dir():
    if not os.path.isfile(CONFIG_FILE):
        return None
    with open(CONFIG_FILE) as f:
        for line in f:
            line = line.strip()
            if line.startswith("output="):
                return os.path.expanduser(line[len("output="):].strip())
    return None


def save_output_dir(path):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        f.write(f"output={path}\n")


def parse_host(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None, None, None

    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    if not host:
        return None, None, None

    return host, port, scheme


def check_https_host(host, port, timeout):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw_sock = None
    tls_sock = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        raw_sock = None

        proto = tls_sock.selected_alpn_protocol()
        if proto == "h2":
            return "h2", None

        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        ).encode()

        tls_sock.sendall(req)

        buf = b""
        tls_sock.settimeout(timeout)
        try:
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\r\n\r\n" in buf:
                    break
        except socket.timeout:
            pass

        headers = buf.decode("utf-8", errors="ignore").lower()
        ka = not bool(re.search(r"connection:\s*close", headers))
        return "http/1.1", ka

    except Exception:
        return None, None

    finally:
        for s in (tls_sock, raw_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass


def check_http_host(host, port, timeout):
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: keep-alive\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    ).encode()

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(req)

        buf = b""
        sock.settimeout(timeout)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\r\n\r\n" in buf:
                    break
        except socket.timeout:
            pass

        headers = buf.decode("utf-8", errors="ignore").lower()
        return not bool(re.search(r"connection:\s*close", headers))

    except Exception:
        return None

    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_host(raw, timeout):
    host, port, scheme = parse_host(raw)
    if not host:
        return raw.strip(), "invalid", None

    label = host if port in (80, 443) else f"{host}:{port}"

    if scheme == "http":
        ka = check_http_host(host, port, timeout)
        if ka is None:
            return label, "unreachable", None
        return label, "http1_only", ka

    proto, ka = check_https_host(host, port, timeout)

    if proto is None:
        return label, "unreachable", None
    if proto == "h2":
        return label, "http2", None

    return label, "http1_only", ka


def fmt(host, verdict, ka):
    if verdict == "http2":
        return f"{RD}[-]{R} {DM}{host:<45}{R} {DM}http/2 - skip{R}"
    if verdict == "unreachable":
        return f"{MG}[!]{R} {DM}{host:<45}{R} {DM}unreachable{R}"
    if verdict == "invalid":
        return f"{YL}[?]{R} {DM}{host:<45}{R} {DM}invalid{R}"
    if ka:
        return f"{GR}{B}[+]{R} {B}{host:<45}{R} {GR}http/1.1  keep-alive{R}"
    return f"{YL}[~]{R} {host:<45} {YL}http/1.1  no keep-alive{R}"


def main():
    parser = argparse.ArgumentParser(prog="http1.1", add_help=True)
    parser.add_argument("name", nargs="?", help="scan label / output directory name")
    parser.add_argument("hosts", nargs="?", help="file with one host per line")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, metavar="N")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="S")
    parser.add_argument("--output", metavar="PATH", help="set output base directory and save to config")
    args = parser.parse_args()

    # --output: set config and exit
    if args.output:
        path = os.path.expanduser(args.output)
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            print(f"{RD}[!] could not create directory: {e}{R}")
            sys.exit(1)
        save_output_dir(path)
        print(f"{GR}[+]{R} output directory set: {B}{path}{R}")
        sys.exit(0)

    # no-args: show help and exit cleanly
    if not args.name and not args.hosts:
        parser.print_help()
        sys.exit(0)

    # check config before anything else
    base_dir = load_output_dir()
    if not base_dir:
        print(f"{RD}[!]{R} no output directory set, use: {B}http1.1 --output /path/to/dir{R}")
        sys.exit(1)

    # missing one of the two positional args
    if not args.name or not args.hosts:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args.hosts):
        print(f"{RD}[!] {args.hosts}: file not found{R}")
        sys.exit(1)

    with open(args.hosts) as f:
        hosts = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]

    if not hosts:
        print(f"{YL}[!] no hosts in file{R}")
        sys.exit(0)

    out_dir = os.path.join(base_dir, args.name)
    ka_path = os.path.join(out_dir, "keepalive.txt")
    no_ka_path = os.path.join(out_dir, "no_keepalive.txt")
    os.makedirs(out_dir, exist_ok=True)

    print(BANNER)
    print(f"{CY}[*]{R} name     {args.name}")
    print(f"{CY}[*]{R} hosts    {args.hosts} ({len(hosts)})")
    print(f"{CY}[*]{R} threads  {args.threads}  timeout  {args.timeout}s")
    print(f"{CY}[*]{R} output   {out_dir}")
    print(f"{DM}{'-'*60}{R}\n")

    ka_results = []
    no_ka_results = []
    counts = {"http2": 0, "unreachable": 0, "http1_only": 0}

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h, args.timeout): h for h in hosts}
        for future in as_completed(futures):
            try:
                host, verdict, ka = future.result()
            except Exception as e:
                print(f"{YL}[!] {e}{R}")
                continue

            print(fmt(host, verdict, ka))

            if verdict == "http1_only":
                counts["http1_only"] += 1
                if ka:
                    ka_results.append(host)
                else:
                    no_ka_results.append(host)
            elif verdict in counts:
                counts[verdict] += 1

    with open(ka_path, "w") as f:
        f.write("\n".join(ka_results) + ("\n" if ka_results else ""))

    with open(no_ka_path, "w") as f:
        f.write("\n".join(no_ka_results) + ("\n" if no_ka_results else ""))

    print(f"\n{DM}{'-'*60}{R}")
    print(f"{GR}[+]{R} http/1.1 + keep-alive   {B}{len(ka_results)}{R} hosts -> {ka_path}")
    print(f"{YL}[~]{R} http/1.1 + no keep-alive {B}{len(no_ka_results)}{R} hosts -> {no_ka_path}")
    print(f"{RD}[-]{R} http/2 discarded         {B}{counts['http2']}{R} hosts")
    print(f"{MG}[!]{R} unreachable              {B}{counts['unreachable']}{R} hosts")
    print()


if __name__ == "__main__":
    main()
