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
    QTYPE,
    RCODE,
    RR,
)

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
        self.banned_cname = normalize_name(cfg.get("banned_cname", "banned.lan"))
        self.banned_mode = cfg.get("banned_mode", "suffix").lower()
        self.banned_list_paths = cfg.get("banned_list")
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

        # Ensure banned_cname label is known to dnslib
        self.banned_label = DNSLabel(self.banned_cname)

    # ------------------------------------------------------------------
    def _is_banned(self, qname: str) -> bool:
        qname_n = normalize_name(qname)
        if self.banned_mode == "exact":
            return qname_n in self.banned_set
        # suffix match: domain itself or any subdomain
        for banned in self.banned_set:
            if qname_n == banned or qname_n.endswith("." + banned):
                return True
        return False

    # ------------------------------------------------------------------
    def _answer_cname(self, request:DNSRecord, qname_label: DNSLabel, target_label: DNSLabel) -> DNSRecord:
        logging.info(f" └ CNAME {target_label}")
        reply = request.reply()
        rr = RR(rname=qname_label, rtype=QTYPE.CNAME, rclass=1, ttl=self.ttl, rdata=DNSCNAME(target_label))
        reply.add_answer(rr)
        return reply

    # ------------------------------------------------------------------
    def _answer_a(self, request:DNSRecord, qname_label: DNSLabel, ip: str) -> DNSRecord:
        logging.info(f" └ A {ip}")
        reply = request.reply()
        rr = RR(rname=qname_label, rtype=QTYPE.A, rclass=1, ttl=self.ttl, rdata=DNSA(ip))
        reply.add_answer(rr)
        return reply

    # ------------------------------------------------------------------
    def _answer_aaaa_nodata(self, request:DNSRecord, qname_label: DNSLabel) -> DNSRecord:
        reply = request.reply()
        # No answers -> forces stub to fall back to A.
        return reply

    # ------------------------------------------------------------------
    def _answer_nxdomain(self, request:DNSRecord, qname_label: DNSLabel) -> DNSRecord:
        logging.info(" → NXDOMAIN")
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    # ------------------------------------------------------------------
    def resolve(self, request: DNSRecord, handler) -> DNSRecord:  # noqa: D401
        qname_label = request.q.qname
        qname = str(qname_label)
        qtype = request.q.qtype

        logging.info(f"Query: {qname} {QTYPE[qtype]}")

        # banned?
        if self._is_banned(qname):
            logging.info(f" ├ banned: {qname_label} -> {self.banned_label}" )
            return self._answer_cname(request, qname_label, self.banned_label)

        qname_n = normalize_name(qname)

        # direct A?
        if qtype in (QTYPE.A, QTYPE.ANY):
            ip = self.a_records.get(qname_n)
            if ip:
                return self._answer_a(request, qname_label, ip)

        # direct CNAME?
        target = self.cname_records.get(qname_n)
        if target:
            return self._answer_cname(request, qname_label, DNSLabel(target))

        # If queried for AAAA and we have an A record, some stub resolvers like a synthetic mapping?
        # We'll just return empty NOERROR so they try A.
        if qtype == QTYPE.AAAA:
            if qname_n in self.a_records or qname_n in self.cname_records:
                return self._answer_aaaa_nodata(request, qname_label)

        # Nothing known
        return self._answer_nxdomain(request, qname_label)


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
    parser = argparse.ArgumentParser(description="YAML-configurable DNS server with banned domains.")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s : %(message)s")

    cfg = load_config(args.config)

    listen = cfg.get("listen", "127.0.0.1")
    port = int(cfg.get("port", 53))

    resolver = YamlResolver(cfg)

    # UDP only for now; add TCP if needed.
    server = DNSServer(resolver, port=port, address=listen, tcp=False, logger=DumbLogger)

    logging.info(f"Starting YAML DNS server on {listen}:{port}")
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