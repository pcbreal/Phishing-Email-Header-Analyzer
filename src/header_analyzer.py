#!/usr/bin/env python3
import sys
import argparse
import re
from email import policy
from email.parser import BytesParser
from colorama import Fore, Style, init as colorama_init

colorama_init()

GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
DIM = Style.DIM
RESET = Style.RESET_ALL

def load_raw_bytes(path: str | None) -> bytes:
    if path:
        with open(path, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()

def parse_message(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)

def get_header(msg, name):
    return msg.get(name, "")

def extract_auth_results(msg):
    spf = dkim = dmarc = ""
    auth_lines = []

    for h in msg.get_all("Authentication-Results", []):
        auth_lines.append(h)
        m = re.search(r"spf=(pass|fail|none|neutral|softfail|temperror|permerror)", h, re.I)
        if m and not spf: spf = m.group(1).lower()
        m = re.search(r"dkim=(pass|fail|none|neutral|temperror|permerror)", h, re.I)
        if m and not dkim: dkim = m.group(1).lower()
        m = re.search(r"dmarc=(pass|fail|none|quarantine|reject|temperror|permerror)", h, re.I)
        if m and not dmarc: dmarc = m.group(1).lower()

    for h in msg.get_all("Received-SPF", []):
        auth_lines.append(h)
        if not spf:
            m = re.search(r"^(pass|fail|softfail|neutral|none)", h, re.I)
            if m: spf = m.group(1).lower()

    return {"spf": spf or "unknown", "dkim": dkim or "unknown", "dmarc": dmarc or "unknown", "raw": auth_lines}

def colorize(v):
    v = v.lower()
    if v == "pass":
        return f"{GREEN}{v.upper()}{RESET}"
    if v in ("fail", "reject", "quarantine"):
        return f"{RED}{v.upper()}{RESET}"
    return f"{YELLOW}{v.upper()}{RESET}"

def extract_received_chain(msg):
    hops = msg.get_all("Received", [])
    chain = []
    for idx, h in enumerate(hops):
        ip = None
        host = None
        ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", h)
        if ip_m: ip = ip_m.group(0)
        host_m = re.search(r"from\s+([^\s\(\);]+)", h, re.I)
        if host_m: host = host_m.group(1)
        chain.append({"index": idx, "host": host, "ip": ip, "raw": h})
    return chain

def domain_from_addr(addr):
    if not addr: return ""
    m = re.search(r"<([^>]+)>", addr);  addr = m.group(1) if m else addr
    m = re.search(r"@([A-Za-z0-9\.\-\_]+)", addr)
    return m.group(1).lower() if m else ""

def looks_like_homograph(domain: str) -> bool:
    if not domain: return False
    patterns = [("1","i"),("0","o"),("rn","m"),("vv","w")]
    d = domain.lower()
    score = 0
    for a,b in patterns:
        score += d.count(a)
    return score >= 2

def analyze_anomalies(msg, auth, chain):
    anomalies = []
    frm = get_header(msg, "From")
    rpath = get_header(msg, "Return-Path")
    rto = get_header(msg, "Reply-To")
    msgid = get_header(msg, "Message-ID")

    from_dom = domain_from_addr(frm)
    rpath_dom = domain_from_addr(rpath)
    rto_dom = domain_from_addr(rto)

    if auth["spf"] in ("fail", "softfail", "unknown"):
        anomalies.append("SPF is not strong PASS (fail/soft/unknown).")
    if auth["dmarc"] in ("fail", "reject", "quarantine", "unknown"):
        anomalies.append("DMARC not passing → check alignment and policy.")
    if from_dom and rpath_dom and from_dom != rpath_dom:
        anomalies.append("From domain != Return-Path domain.")
    if rto_dom and from_dom and rto_dom != from_dom:
        anomalies.append("Reply-To domain != From domain (possible redirection).")
    if looks_like_homograph(from_dom):
        anomalies.append(f"Suspicious lookalike in From domain: {from_dom}")
    if not msg.get("Authentication-Results"):
        anomalies.append("Missing Authentication-Results header.")
    if msgid and from_dom and from_dom not in msgid.lower():
        anomalies.append("Message-ID domain does not match From domain (not always bad).")
    if not chain:
        anomalies.append("No Received headers found (rare and suspicious).")
    return anomalies

def verdict(auth, anomalies):
    score = 0
    if auth["spf"] == "pass": score += 1
    if auth["dkim"] == "pass": score += 1
    if auth["dmarc"] == "pass": score += 2
    score -= len(anomalies)
    if score >= 2 and len(anomalies) <= 1: return f"{GREEN}LOW RISK{RESET}"
    if score >= 0: return f"{YELLOW}MEDIUM RISK{RESET}"
    return f"{RED}HIGH RISK{RESET}"

def print_report(msg):
    auth = extract_auth_results(msg)
    chain = extract_received_chain(msg)
    anomalies = analyze_anomalies(msg, auth, chain)

    print("=== Auth Summary ===")
    print(f"SPF: {colorize(auth['spf'])}  DKIM: {colorize(auth['dkim'])}  DMARC: {colorize(auth['dmarc'])}\n")

    print("=== Identities ===")
    print(f"From:        {get_header(msg, 'From')}")
    print(f"Return-Path: {get_header(msg, 'Return-Path')}")
    print(f"Reply-To:    {get_header(msg, 'Reply-To')}")
    print(f"Message-ID:  {get_header(msg, 'Message-ID')}")
    print(f"Date:        {get_header(msg, 'Date')}\n")

    print("=== Received Chain (top=most recent) ===")
    if not chain:
        print("No hops found.")
    else:
        for i, hop in enumerate(chain):
            mark = "<- first sending host" if i == len(chain) - 1 else ""
            host = hop["host"] or "?"
            ip = hop["ip"] or "?"
            print(f"[{i}] {host} ({ip}) {DIM}{mark}{RESET}")
    print()

    print("=== Anomalies ===")
    if anomalies:
        for a in anomalies:
            sev = RED if any(x in a.lower() for x in ["fail", "suspicious", "not", "no ", "!="]) else YELLOW
            print(sev + "- " + a + RESET)
    else:
        print(GREEN + "None detected." + RESET)
    print()

    print(f"Verdict: {verdict(auth, anomalies)}")

def main():
    ap = argparse.ArgumentParser(description="Phishing Email Header Analyzer")
    ap.add_argument("--file", "-f", help="Path to .eml or text file with raw headers. If omitted, reads from STDIN.")
    args = ap.parse_args()
    raw = load_raw_bytes(args.file)
    msg = parse_message(raw)
    print_report(msg)

if __name__ == "__main__":
    main()
