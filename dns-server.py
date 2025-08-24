#!.venv/bin/python3

import argparse
import ipaddress
import logging
import os
import socket
import sys
from typing import Dict, Optional, Set

import yaml
from dnslib.server import BaseResolver, DNSServer
from dnslib import (
    A as DNSA,
    AAAA as DNSAAAA,
    CNAME as DNSCNAME,
    DNSLabel,
    DNSRecord,
    DNSError,
    QTYPE,
    RCODE,
    RR,
)

CONFIG_PATH = "dns/config.yaml"

class DumbLogger: # Dummy logger to satisfy dnslib's interface
    def __init__(self,log="",prefix=True,logf=None):pass
    def log_pass(self,*args):pass
    def log_prefix(self,handler):pass
    def log_recv(self,handler,data=""):pass
    def log_send(self,handler,data=""):pass
    def log_request(self,handler,request=""):pass
    def log_reply(self,handler,reply=""):pass
    def log_truncated(self,handler,reply=""):pass
    def log_error(self,handler,e):pass
    def log_data(self,dnsobj):pass



# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def detect_local_ip(target_host: str = "8.8.8.8", target_port: int = 53) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_host, target_port))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()

def load_banned(path: str) -> Set[str]:
    banned: Set[str] = set()
    if not path:
        return banned
    
    if path.startswith("http://") or path.startswith("https://"):
        import requests
        try:
            response = requests.get(path)
            response.raise_for_status()
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                banned.add(normalize_name(line))

        except requests.RequestException as e:
            logging.error(f"Failed to load banned list from {path}: {e}")
            return banned
        return banned

    if not os.path.exists(path):
        logging.warning(f"Banned list file {path} not found; continuing with none.")
        return banned
    
    with open(path, "r", encoding="utf-8") as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            banned.add(normalize_name(line))
    return banned


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------
class YamlResolver(BaseResolver):
    def __init__(self, cfg: dict):
        self.ttl = int(cfg.get("ttl", 60))
        self.banned_ip = normalize_name(cfg.get("banned_ip", "127.0.0.1"))
        self.banned_mode = cfg.get("banned_mode", "suffix").lower()
        self.banned_list_paths = cfg.get("banned_list")
        self.upstream_dns = (cfg.get("upstream_dns") or "8.8.8.8")
        self.banned_set: Set[str] = set()
        for path in self.banned_list_paths if isinstance(self.banned_list_paths, list) else [self.banned_list_paths]:
            if path:
                self.banned_set.update(load_banned(path))

        # Records
        recs = cfg.get("records", {})
        self.a_records: Dict[str, str] = {
            normalize_name(k): v for k, v in recs.get("A", {}).items()
        }
        self.cname_records: Dict[str, str] = {
            normalize_name(k): normalize_name(v) for k, v in recs.get("CNAME", {}).items()
        }

        # local server ip (resolved later if needed)
        cfg_ip = cfg.get("server_ip")
        self.server_ip = normalize_name(cfg_ip) if cfg_ip else None

        # Fill in actual server IP now (after we may have bound socket?)
        if (self.server_ip is None) or (self.server_ip in ("", "auto", "none", "null")):
            try:
                self.server_ip = detect_local_ip()
                logging.info(f"Auto-detected local IP: {self.server_ip}")
            except Exception as e:  # pragma: no cover - network env specific
                logging.error(f"Failed to auto-detect local IP: {e}")
                self.server_ip = "127.0.0.1"

        logging.info(f"Using upstream DNS: {self.upstream_dns}")

        # Replace special "server" value in A records with detected IP
        for name, value in list(self.a_records.items()):
            if isinstance(value, str) and value.strip().lower() == "server":
                self.a_records[name] = self.server_ip

        # Validate IP literals in A records
        for n, ip in list(self.a_records.items()):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logging.error(f"Invalid IP for A record {n}: {ip}", n, ip)
                del self.a_records[n]

    # ------------------------------------------------------------------
    def _is_banned(self, qname_n: str) -> bool:
        if self.banned_mode == "exact":
            return qname_n in self.banned_set
        # suffix match: domain itself or any subdomain
        for banned in self.banned_set:
            if qname_n == banned or qname_n.endswith("." + banned):
                return True
        return False

    # ------------------------------------------------------------------
    def _answer_cname(self, request:DNSRecord, qname_label: DNSLabel, target_label: DNSLabel, source_ip: str) -> DNSRecord:
        logging.info(f"Local    - {source_ip}: {QTYPE[request.q.qtype]} {qname_label} -> {target_label}")
        reply = request.reply()
        rr = RR(rname=qname_label, rtype=QTYPE.CNAME, rclass=1, ttl=self.ttl, rdata=DNSCNAME(target_label))
        reply.add_answer(rr)
        return reply

    # ------------------------------------------------------------------
    def _answer_a(self, request:DNSRecord, qname_label: DNSLabel, ip: str, source_ip: str) -> DNSRecord:
        logging.info(f"Local    - {source_ip}: {QTYPE[request.q.qtype]} {qname_label} -> {ip}")
        reply = request.reply()
        reply.add_answer(RR(rname=qname_label, rtype=QTYPE.A, rclass=1, ttl=self.ttl, rdata=DNSA(ip)))
        return reply

    # ------------------------------------------------------------------
    def _answer_aaaa_nodata(self, request:DNSRecord, qname_label: DNSLabel, source_ip: str) -> DNSRecord:
        reply = request.reply()
        # No answers -> forces stub to fall back to A.
        return reply

    # ------------------------------------------------------------------
    def _answer_banned(self, request:DNSRecord, qname_label: DNSLabel, source_ip: str) -> DNSRecord:
        logging.info(f"Banned: {source_ip}: {QTYPE[request.q.qtype]} {qname_label} -> {self.banned_ip}" )
        reply = request.reply()
        reply.add_answer(RR(rname=qname_label, rtype=QTYPE.A, rclass=1, ttl=self.ttl, rdata=DNSA(self.banned_ip)))
        return reply
    
    # ------------------------------------------------------------------
    def _answer_upstream(self, request: DNSRecord, qname_label: DNSLabel, source_ip: str) -> DNSRecord:
        try:
            # Create UDP socket to upstream DNS
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream_sock.settimeout(2)  # seconds
            upstream_sock.sendto(request.pack(), (self.upstream_dns, 53))  # Send to upstream DNS

            # Receive response from upstream DNS
            data, _ = upstream_sock.recvfrom(4096)
            upstream_sock.close()
    
            reply = DNSRecord.parse(data)

            log_data = str(reply.a)
            while "  " in log_data:  # Clean up double spaces
                log_data = log_data.replace("  ", " ")  # Clean up whitespace
            log_data = log_data.split(" ")
            logging.info(f"Upstream - {source_ip}: {QTYPE[request.q.qtype]} {qname_label} -> {log_data[3]} {log_data[4]}")
            return reply

        except DNSError as e:
            logging.info(f"Upstream - {source_ip}: {QTYPE[request.q.qtype]} {qname_label} -> not found")
            return reply
        except Exception as e:
            logging.error(f"Failed to query upstream DNS: {e} {type(e).__name__} - {source_ip} {qname_label}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

    # ------------------------------------------------------------------
    def resolve(self, request: DNSRecord, handler) -> DNSRecord:  # noqa: D401
        qname_label = request.q.qname
        qname = str(qname_label)
        qtype = request.q.qtype
        source_ip = handler.client_address[0] if handler else "unknown"
        qname_n = normalize_name(qname)

        # banned?
        if self._is_banned(qname_n):
            return self._answer_banned(request, qname_label, source_ip)


        # direct A?
        if qtype in (QTYPE.A, QTYPE.ANY):
            ip = self.a_records.get(qname_n)
            if ip:
                return self._answer_a(request, qname_label, ip, source_ip)

        # direct CNAME?
        target = self.cname_records.get(qname_n)
        if target:
            return self._answer_cname(request, qname_label, DNSLabel(target), source_ip)

        # If queried for AAAA and we have an A record, some stub resolvers like a synthetic mapping?
        # We'll just return empty NOERROR so they try A.
        if qtype == QTYPE.AAAA:
            if qname_n in self.a_records or qname_n in self.cname_records:
                return self._answer_aaaa_nodata(request, qname_label, source_ip)

        # Nothing known
        return self._answer_upstream(request, qname_label, source_ip)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ValueError("Top-level YAML must be a mapping/dict")
    return cfg


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:

    logging.basicConfig(level=logging.INFO, format="%(asctime)s : %(message)s")

    cfg = load_config(CONFIG_PATH)

    listen = cfg.get("listen", "127.0.0.1")
    port = int(cfg.get("port", 53))

    resolver = YamlResolver(cfg)

    # UDP only for now; add TCP if needed.
    server = DNSServer(resolver, port=port, address=listen, tcp=False, logger=DumbLogger)

    logging.info(f"Starting DNS server on {listen}:{port}")
    try:
        server.start()
    except PermissionError:
        logging.error(f"Permission denied binding {listen}:{port}. Try sudo or set CAP_NET_BIND_SERVICE.")
        return 1
    except KeyboardInterrupt:
        logging.info("Shutting down server.")
        server.stop()
        return 0

if __name__ == "__main__":
    sys.exit(main())