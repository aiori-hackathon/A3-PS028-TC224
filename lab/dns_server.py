#!/usr/bin/env python3
"""
PS-028 Controlled DNS Server (Work Package A3)
Authoritative, non-blocking dual-stack (UDP and TCP) DNS server for Happy Eyeballs testing.
"""

import argparse
import asyncio
import datetime
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading
import time

# Strict dependency check
try:
    import dns
    import dns.flags
    import dns.message
    import dns.name
    import dns.rcode
    import dns.rdatatype
    import dns.rrset
except ImportError:
    sys.stderr.write("FATAL: dnspython is missing. Required package: python3-dnspython (2.6.1-1ubuntu1)\n")
    sys.exit(1)

REQUIRED_DNSPYTHON = "2.6.1"
if dns.__version__ != REQUIRED_DNSPYTHON:
    sys.stderr.write(f"FATAL: dnspython version mismatch: expected {REQUIRED_DNSPYTHON}, found {dns.__version__}\n")
    sys.exit(1)


def validate_config_dict(data):
    """
    Strict validation of configuration data dictionary.
    Rejects wrong types, booleans masquerading as integers, invalid IPs, and missing keys.
    """
    if type(data) is not dict:
        raise TypeError("Configuration root must be a JSON object")

    expected_keys = {"zone", "default_ttl", "rules", "behavior"}
    if set(data.keys()) != expected_keys:
        raise ValueError(f"Root keys mismatch: expected {expected_keys}, got {set(data.keys())}")

    if type(data["zone"]) is not str or not data["zone"].endswith("."):
        raise ValueError("zone must be a fully qualified domain name ending with a dot (e.g., 'he.test.')")

    if type(data["default_ttl"]) is not int or type(data["default_ttl"]) is bool:
        raise TypeError("default_ttl must be an integer, not boolean")
    if data["default_ttl"] < 0:
        raise ValueError("default_ttl must be non-negative")

    if type(data["behavior"]) is not dict:
        raise TypeError("behavior must be an object")
    if set(data["behavior"].keys()) != {"unknown_domain_rcode", "unsupported_type_rcode"}:
        raise ValueError("behavior keys mismatch")
    for b_key in ("unknown_domain_rcode", "unsupported_type_rcode"):
        code_str = data["behavior"][b_key]
        if type(code_str) is not str:
            raise TypeError(f"behavior.{b_key} must be a string")
        try:
            dns.rcode.from_text(code_str)
        except Exception as e:
            raise ValueError(f"Invalid RCODE in behavior.{b_key}: {e}")

    rules = data["rules"]
    if type(rules) is not dict or set(rules.keys()) != {"A", "AAAA"}:
        raise ValueError("rules must be an object containing exactly 'A' and 'AAAA'")

    for qtype in ("A", "AAAA"):
        rule = rules[qtype]
        if type(rule) is not dict or set(rule.keys()) != {"address", "delay_ms", "rcode"}:
            raise ValueError(f"rules.{qtype} must contain exactly address, delay_ms, rcode")

        if type(rule["address"]) is not str:
            raise TypeError(f"rules.{qtype}.address must be string")
        if qtype == "A":
            ipaddress.IPv4Address(rule["address"])
        else:
            ipaddress.IPv6Address(rule["address"])

        if type(rule["delay_ms"]) is not int or type(rule["delay_ms"]) is bool:
            raise TypeError(f"rules.{qtype}.delay_ms must be an integer, not boolean")
        if rule["delay_ms"] < 0:
            raise ValueError(f"rules.{qtype}.delay_ms must be non-negative")

        if type(rule["rcode"]) is not str:
            raise TypeError(f"rules.{qtype}.rcode must be string")
        try:
            dns.rcode.from_text(rule["rcode"])
        except Exception as e:
            raise ValueError(f"Invalid RCODE in rules.{qtype}: {e}")

    return data


def is_supported_hostname(qname_str: str, zone: str) -> bool:
    """
    Validates whether the requested domain name is supported.
    Allowed hostnames:
      - The apex zone (e.g. 'he.test.')
      - Valid trial hostnames: 'trial-<id>.<zone>' (e.g. 'trial-1.he.test.', 'trial-02.he.test.')
        where <id> is a non-empty alphanumeric/hyphen/underscore identifier.
    Returns True if valid, False otherwise (triggers NXDOMAIN).
    """
    qname = qname_str.lower().strip()
    zone_norm = zone.lower().strip()
    if not qname.endswith("."):
        qname += "."
    if not zone_norm.endswith("."):
        zone_norm += "."

    if qname == zone_norm:
        return True

    suffix = "." + zone_norm
    if qname.endswith(suffix):
        sublabel = qname[:-len(suffix)]
        # Must be a single label (no additional dots) and match trial-<id>
        if "." not in sublabel and re.fullmatch(r"trial-[a-zA-Z0-9_-]+", sublabel):
            return True

    return False


class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.server.handle_udp_query(data, addr, self.transport))

    def error_received(self, exc):
        self.server.log_event(f"[WARN] UDP socket error: {exc}")


class ControlledDNSServer:
    def __init__(self, bind_ip, port, config_path, log_file, pid_file):
        self.bind_ip = bind_ip
        self.port = port
        self.config_path = Path(config_path).resolve()
        self.log_file = Path(log_file).resolve()
        self.pid_file = Path(pid_file).resolve()
        self.config = {}
        self.log_fp = None
        self.udp_transport = None
        self.tcp_server = None
        self.is_running = False

    def load_configuration(self):
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        validated = validate_config_dict(data)
        self.config = validated

    def open_log(self):
        self.log_fp = open(self.log_file, "a", encoding="utf-8", buffering=1)

    def log_event(self, message):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        if self.log_fp and not self.log_fp.closed:
            self.log_fp.write(f"[{timestamp}] {message}\n")
            self.log_fp.flush()

    def log_query(self, recv_iso, client_str, proto, qname, qtype, rcode_str, delay_ms, resp_iso, elapsed_ms):
        log_line = (
            f"{recv_iso} client={client_str} proto={proto} qname={qname} qtype={qtype} "
            f"rcode={rcode_str} delay_ms={delay_ms:.1f} resp_timestamp_iso={resp_iso} "
            f"elapsed_ms={elapsed_ms:.2f}\n"
        )
        if self.log_fp and not self.log_fp.closed:
            self.log_fp.write(log_line)
            self.log_fp.flush()

    def handle_sighup(self):
        self.log_event("[INFO] SIGHUP received. Reloading configuration...")
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                new_data = json.load(f)
            validated = validate_config_dict(new_data)
            self.config = validated
            self.log_event("[INFO] SIGHUP config reload applied successfully.")
        except Exception as e:
            self.log_event(f"[ERROR] SIGHUP config reload rejected: {e}. Retaining previous active configuration.")

    def build_response(self, request_msg):
        """
        Builds DNS response based on current active rules.
        Preserves the requested hostname in answers and logs.
        Returns: (response_wire_bytes, qname_str, qtype_str, rcode_str, delay_s)
        """
        if not request_msg.question:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.FORMERR)
            return resp.to_wire(), "none", "none", "FORMERR", 0.0

        q = request_msg.question[0]
        # Preserve original requested hostname (with trailing dot)
        req_qname = q.name.to_text()
        if not req_qname.endswith("."):
            req_qname += "."
        qname_lower = req_qname.lower()
        qtype_str = dns.rdatatype.to_text(q.rdtype)

        resp = dns.message.make_response(request_msg)
        resp.flags |= dns.flags.AA
        resp.flags &= ~dns.flags.RA

        zone = self.config["zone"].lower()
        default_ttl = self.config["default_ttl"]
        behavior = self.config["behavior"]
        rules = self.config["rules"]

        delay_s = 0.0

        if is_supported_hostname(qname_lower, zone):
            if qtype_str in rules:
                rule = rules[qtype_str]
                delay_s = rule["delay_ms"] / 1000.0
                rcode = dns.rcode.from_text(rule["rcode"])
                resp.set_rcode(rcode)
                if rcode == dns.rcode.NOERROR:
                    rr = dns.rrset.from_text(req_qname, default_ttl, "IN", qtype_str, rule["address"])
                    resp.answer.append(rr)
            else:
                # Unsupported record type on existing zone -> NODATA
                delay_s = 0.0
                rcode = dns.rcode.from_text(behavior.get("unsupported_type_rcode", "NOERROR"))
                resp.set_rcode(rcode)
        else:
            # Unknown domain -> NXDOMAIN
            delay_s = 0.0
            rcode = dns.rcode.from_text(behavior.get("unknown_domain_rcode", "NXDOMAIN"))
            resp.set_rcode(rcode)

        rcode_str = dns.rcode.to_text(resp.rcode())
        return resp.to_wire(), req_qname, qtype_str, rcode_str, delay_s

    async def handle_udp_query(self, data, addr, transport):
        t0 = time.time()
        recv_iso = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        client_str = f"{addr[0]}:{addr[1]}"

        try:
            req = dns.message.from_wire(data)
        except Exception as e:
            self.log_event(f"[WARN] Failed to parse UDP message from {client_str}: {e}")
            return

        resp_wire, qname, qtype, rcode_str, delay_s = self.build_response(req)

        if delay_s > 0:
            await asyncio.sleep(delay_s)

        try:
            transport.sendto(resp_wire, addr)
        except Exception as e:
            self.log_event(f"[ERROR] Failed to send UDP response to {client_str}: {e}")

        t1 = time.time()
        resp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        elapsed_ms = (t1 - t0) * 1000.0

        self.log_query(recv_iso, client_str, "UDP", qname, qtype, rcode_str, delay_s * 1000.0, resp_iso, elapsed_ms)

    async def handle_tcp_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        client_str = f"{peer[0]}:{peer[1]}" if peer else "unknown"

        while self.is_running:
            try:
                len_bytes = await reader.readexactly(2)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            except Exception as e:
                self.log_event(f"[WARN] TCP read error from {client_str}: {e}")
                break

            msg_len = int.from_bytes(len_bytes, "big")
            if msg_len == 0:
                continue

            try:
                data = await reader.readexactly(msg_len)
            except Exception as e:
                self.log_event(f"[WARN] TCP message read error from {client_str}: {e}")
                break

            t0 = time.time()
            recv_iso = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")

            try:
                req = dns.message.from_wire(data)
            except Exception as e:
                self.log_event(f"[WARN] Failed to parse TCP message from {client_str}: {e}")
                break

            resp_wire, qname, qtype, rcode_str, delay_s = self.build_response(req)

            if delay_s > 0:
                await asyncio.sleep(delay_s)

            resp_len_bytes = len(resp_wire).to_bytes(2, "big")
            try:
                writer.write(resp_len_bytes + resp_wire)
                await writer.drain()
            except Exception as e:
                self.log_event(f"[ERROR] TCP write error to {client_str}: {e}")
                break

            t1 = time.time()
            resp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
            elapsed_ms = (t1 - t0) * 1000.0

            self.log_query(recv_iso, client_str, "TCP", qname, qtype, rcode_str, delay_s * 1000.0, resp_iso, elapsed_ms)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    def write_pid(self):
        pid = os.getpid()
        with open(self.pid_file, "w", encoding="utf-8") as f:
            f.write(f"{pid}\n")

    def remove_pid(self):
        try:
            if self.pid_file.is_file():
                with open(self.pid_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if content == str(os.getpid()):
                    self.pid_file.unlink(missing_ok=True)
        except Exception:
            pass

    async def start(self):
        self.load_configuration()
        self.open_log()
        self.log_event(f"[INFO] Initializing DNS Server on {self.bind_ip}:{self.port}...")

        loop = asyncio.get_running_loop()

        # Register signal handlers if in main thread
        if threading.current_thread() is threading.main_thread():
            try:
                loop.add_signal_handler(signal.SIGHUP, self.handle_sighup)
                for sig in (signal.SIGTERM, signal.SIGINT):
                    loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
            except (ValueError, RuntimeError):
                pass

        # Start UDP listener
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: DNSProtocol(self),
                local_addr=(self.bind_ip, self.port)
            )
            self.udp_transport = transport
        except Exception as e:
            self.log_event(f"[FATAL] Failed to bind UDP listener on {self.bind_ip}:{self.port}: {e}")
            raise

        # Start TCP listener
        try:
            server = await asyncio.start_server(
                self.handle_tcp_client,
                host=self.bind_ip,
                port=self.port
            )
            self.tcp_server = server
        except Exception as e:
            self.log_event(f"[FATAL] Failed to bind TCP listener on {self.bind_ip}:{self.port}: {e}")
            self.udp_transport.close()
            raise

        self.is_running = True
        self.write_pid()
        self.log_event(f"[OK] DNS Server active (PID {os.getpid()}) listening on {self.bind_ip}:{self.port} (UDP/TCP).")

        async with self.tcp_server:
            await self.tcp_server.serve_forever()

    async def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        self.log_event("[INFO] Shutting down DNS server...")

        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()

        if self.udp_transport:
            self.udp_transport.close()

        self.remove_pid()
        self.log_event("[OK] DNS server stopped cleanly.")

        if self.log_fp and not self.log_fp.closed:
            self.log_fp.close()


def main():
    parser = argparse.ArgumentParser(description="PS-028 Controlled DNS Server")
    parser.add_argument("--bind", default="10.0.1.1", help="Bind IP address (default: 10.0.1.1)")
    parser.add_argument("--port", type=int, default=53, help="Port (default: 53)")
    parser.add_argument("--config", default="lab/dns_config.json", help="Path to configuration JSON")
    parser.add_argument("--log-file", default="lab/dns.log", help="Path to output log file")
    parser.add_argument("--pid-file", default="lab/dns.pid", help="Path to PID file")

    args = parser.parse_args()

    server = ControlledDNSServer(
        bind_ip=args.bind,
        port=args.port,
        config_path=args.config,
        log_file=args.log_file,
        pid_file=args.pid_file
    )

    try:
        asyncio.run(server.start())
    except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
        pass
    except RuntimeError as e:
        if "Event loop stopped" not in str(e):
            sys.stderr.write(f"FATAL: DNS server terminated unexpectedly: {e}\n")
            sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"FATAL: DNS server terminated unexpectedly: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
