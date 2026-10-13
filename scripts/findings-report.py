#!/usr/bin/env python3
"""
findings-report.py - Chronos honeypot findings report (OpenSearch -> Markdown).

Reads live sensor data (chronos-logs-*, events carrying sensor_id) and writes
reports/findings-<UTC date>.md with:
  collection window and totals, top source countries and ASNs, attacks by MITRE
  technique, top credentials, top commands, bot families (sessions grouped by
  normalized command sequence) with enumeration patterns, HTTP canary paths/UAs.

Exits non-zero if any required section has no data rows (use --allow-empty to
override), so "exit 0" means every section was filled from real data.
Stdlib only; run on the core or through an SSM tunnel to :9200.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DISCOVERY = ["T1082", "T1033", "T1057", "T1016", "T1083"]
TECHNIQUE_NAMES = {
    "T1595": "Active Scanning", "T1595.002": "Vulnerability Scanning", "T1595.003": "Wordlist Scanning",
    "T1592.002": "Gather Victim Host Info: Software", "T1110.001": "Password Guessing",
    "T1078.001": "Valid Accounts: Default Accounts", "T1059.004": "Unix Shell", "T1105": "Ingress Tool Transfer",
    "T1090": "Proxy", "T1190": "Exploit Public-Facing Application", "T1098.004": "SSH Authorized Keys",
    "T1053.003": "Cron", "T1496": "Resource Hijacking", "T1562.004": "Disable or Modify System Firewall",
    "T1070.003": "Clear Command History", "T1098": "Account Manipulation", "T1003.008": "/etc/passwd and /etc/shadow",
    "T1222.002": "Linux File Permissions Modification", "T1082": "System Information Discovery",
    "T1033": "System Owner/User Discovery", "T1057": "Process Discovery",
    "T1016": "System Network Configuration Discovery", "T1083": "File and Directory Discovery",
}
REQUIRED_SECTIONS = [
    "Collection window and totals",
    "Top source countries and ASNs",
    "Attacks by MITRE technique",
    "Top credentials tried",
    "Top commands",
    "Bot families and enumeration patterns",
    "HTTP canary paths and user agents",
]

# Command normalization: strip per-victim / per-campaign noise so the same bot groups together.
KEEP_TOKENS = {"base64", "sha256sum", "sha1sum", "md5sum", "aarch64", "armv7l", "x86_64", "i686", "ipv4", "ipv6"}


def _random_token(m: re.Match) -> str:
    tok = m.group(0)
    digits = sum(c.isdigit() for c in tok)
    letters = sum(c.isalpha() for c in tok)
    return "<TOK>" if digits >= 2 and letters >= 2 and tok.lower() not in KEEP_TOKENS else tok


NORMALIZERS = [
    (re.compile(r"\b(?:https?|ftp|tftp)://\S+", re.I), "<URL>"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2})+"), "<HEXBYTES>"),
    # Keep the key comment: it is often a campaign marker (e.g. "mdrfckr").
    (re.compile(r"\b(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+"), r"\1 <KEY>"),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), "<B64>"),
    (re.compile(r"(\w+):[^\s|\"']+(?=[\"']?\s*\|\s*(?:sudo\s+)?chpasswd)"), r"\1:<PW>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "<HEX>"),
    (re.compile(r"\b[\w-]{6,}\b"), _random_token),
    (re.compile(r"\b\d+\b"), "<N>"),
    (re.compile(r"\s+"), " "),
]


def normalize(cmd: str) -> str:
    for pattern, repl in NORMALIZERS:
        cmd = pattern.sub(repl, cmd)
    return cmd.strip()


def md(text, limit=120) -> str:
    """Attacker-controlled text as a markdown-table-safe code span."""
    text = str(text).replace("\n", " ").replace("|", "\\|")
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


def fenced(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def table(headers, rows) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


class OpenSearch:
    def __init__(self, url, index, base_filter, exclude_ips):
        self.url, self.index = url.rstrip("/"), index
        self.base_filter, self.exclude_ips = base_filter, exclude_ips

    def _req(self, path, body):
        req = urllib.request.Request(f"{self.url}/{path}", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.load(resp)

    def query(self, *filters):
        q = {"bool": {"filter": list(self.base_filter) + list(filters)}}
        if self.exclude_ips:
            q["bool"]["must_not"] = [{"terms": {"src_ip": self.exclude_ips}}]
        return q

    def aggs(self, aggs, *filters):
        res = self._req(f"{self.index}/_search", {"size": 0, "track_total_hits": True,
                                                  "query": self.query(*filters), "aggs": aggs})
        return res["hits"]["total"]["value"], res.get("aggregations", {})

    def scan(self, fields, *filters, sort=("timestamp",)):
        """All matching docs via search_after (no scroll context to clean up)."""
        body = {"size": 5000, "_source": fields, "query": self.query(*filters),
                "sort": [{f: "asc"} for f in sort] + [{"_doc": "asc"}]}
        while True:
            hits = self._req(f"{self.index}/_search", body)["hits"]["hits"]
            if not hits:
                return
            for h in hits:
                yield h["_source"]
            body["search_after"] = hits[-1]["sort"]


def terms(field, size=20, **extra):
    agg = {"terms": {"field": field, "size": size}}
    agg.update(extra)
    return agg


def section_window(os_):
    total, a = os_.aggs({
        "first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}},
        "sessions": {"cardinality": {"field": "session"}}, "ips": {"cardinality": {"field": "src_ip"}},
        "honeypot": terms("honeypot", 5),
        "eventid": terms("eventid", 15),
        "daily": {"date_histogram": {"field": "timestamp", "calendar_interval": "1d", "min_doc_count": 0},
                  "aggs": {"ips": {"cardinality": {"field": "src_ip"}}, "sessions": {"cardinality": {"field": "session"}}}},
    })
    if not total:
        return [], {}
    first, last = a["first"]["value_as_string"], a["last"]["value_as_string"]
    span_days = (a["last"]["value"] - a["first"]["value"]) / 86_400_000
    days = [b for b in a["daily"]["buckets"]]
    nonempty = sum(1 for b in days if b["doc_count"])
    lines = [
        table(["Metric", "Value"], [
            ("First event (UTC)", first), ("Last event (UTC)", last),
            ("Span", f"{span_days:.2f} days"), ("Calendar days with events", f"{nonempty} of {len(days)}"),
            ("Events", f"{total:,}"), ("Cowrie sessions (approx.)", f"{a['sessions']['value']:,}"),
            ("Unique source IPs (approx.)", f"{a['ips']['value']:,}"),
        ] + [(f"Events from {b['key']}", f"{b['doc_count']:,}") for b in a["honeypot"]["buckets"]]),
        "",
        "**Daily volume**",
        "",
        table(["Day (UTC)", "Events", "Sessions", "Unique IPs"],
              [(b["key_as_string"][:10], f"{b['doc_count']:,}", f"{b['sessions']['value']:,}", f"{b['ips']['value']:,}")
               for b in days]),
        "",
        "**Event types**",
        "",
        table(["Event", "Count"], [(md(b["key"]), f"{b['doc_count']:,}") for b in a["eventid"]["buckets"]]),
    ]
    return lines, {"first": first, "last": last, "span_days": span_days, "days": nonempty, "total": total}


def section_geo(os_):
    _, a = os_.aggs({
        "countries": terms("geo.country_name", 15, aggs={"ips": {"cardinality": {"field": "src_ip"}},
                                                         "iso": terms("geo.country_iso_code", 1)}),
        "asns": terms("as.organization_name", 15, aggs={"ips": {"cardinality": {"field": "src_ip"}},
                                                        "asn": terms("as.asn", 1),
                                                        "sessions": {"cardinality": {"field": "session"}}}),
        "no_geo": {"missing": {"field": "geo.country_name"}},
    })
    countries = a["countries"]["buckets"]
    asns = a["asns"]["buckets"]
    if not countries or not asns:
        return []
    return [
        "GeoIP: GeoLite2 City/ASN databases bundled with OpenSearch 2.11.1 (built Nov 2023); "
        f"{a['no_geo']['doc_count']:,} events had no country match.",
        "",
        "**By country (ranked by unique attacking IPs)**",
        "",
        table(["Country", "Unique IPs", "Events"],
              [(f"{b['key']} ({b['iso']['buckets'][0]['key'] if b['iso']['buckets'] else '?'})", f"{b['ips']['value']:,}",
                f"{b['doc_count']:,}") for b in sorted(countries, key=lambda b: -b["ips"]["value"])]),
        "",
        "**By autonomous system**",
        "",
        table(["ASN", "Organisation", "Unique IPs", "Sessions", "Events"],
              [(f"AS{b['asn']['buckets'][0]['key']}" if b["asn"]["buckets"] else "?", md(b["key"], 60),
                f"{b['ips']['value']:,}", f"{b['sessions']['value']:,}", f"{b['doc_count']:,}") for b in asns]),
    ]


def section_mitre(os_):
    _, a = os_.aggs({
        "tech": terms("mitre_technique", 30, aggs={"tactic": terms("mitre_tactic", 1),
                                                   "ips": {"cardinality": {"field": "src_ip"}}}),
        "cmd_tech": terms("command_techniques", 30, aggs={"sessions": {"cardinality": {"field": "session"}}}),
    })
    tech = [b for b in a["tech"]["buckets"] if b["key"] != "None"]
    if not tech:
        return []
    lines = [
        "Primary technique per event (Vector catalog + command rules in `config/vector/vector-core.yaml`).",
        "",
        table(["Technique", "Name", "Tactic", "Events", "Unique IPs"],
              [(b["key"], TECHNIQUE_NAMES.get(b["key"], ""),
                b["tactic"]["buckets"][0]["key"] if b["tactic"]["buckets"] else "", f"{b['doc_count']:,}",
                f"{b['ips']['value']:,}") for b in tech]),
    ]
    if a["cmd_tech"]["buckets"]:
        lines += ["", "**All techniques observed in shell commands** (a command can match several)", "",
                  table(["Technique", "Name", "Commands", "Sessions"],
                        [(b["key"], TECHNIQUE_NAMES.get(b["key"], ""), f"{b['doc_count']:,}",
                          f"{b['sessions']['value']:,}") for b in a["cmd_tech"]["buckets"]])]
    return lines


def section_credentials(os_):
    logins = {"terms": {"eventid": ["cowrie.login.failed", "cowrie.login.success"]}}
    total, a = os_.aggs({
        "pairs": {"multi_terms": {"terms": [{"field": "username"}, {"field": "password"}], "size": 25},
                  "aggs": {"ok": {"filter": {"term": {"eventid": "cowrie.login.success"}}},
                           "ips": {"cardinality": {"field": "src_ip"}}}},
        "users": terms("username", 15, aggs={"ips": {"cardinality": {"field": "src_ip"}}}),
        "passwords": terms("password", 15),
        "success": {"filter": {"term": {"eventid": "cowrie.login.success"}}},
        "pair_count": {"cardinality": {"script": {"source": "doc['username'].size()==0||doc['password'].size()==0 ? '' : doc['username'].value + '\\u0000' + doc['password'].value"}}},
    }, logins)
    if not a or not a["pairs"]["buckets"]:
        return []
    return [
        f"{total:,} login attempts, {a['success']['doc_count']:,} accepted by Cowrie "
        f"({a['success']['doc_count'] / total:.1%}); ~{a['pair_count']['value']:,} distinct username/password pairs.",
        "",
        "**Top username/password pairs**",
        "",
        table(["Username", "Password", "Attempts", "Accepted", "Unique IPs"],
              [(md(b["key"][0], 40), md(b["key"][1], 40), f"{b['doc_count']:,}", f"{b['ok']['doc_count']:,}",
                f"{b['ips']['value']:,}") for b in a["pairs"]["buckets"]]),
        "",
        "**Top usernames**",
        "",
        table(["Username", "Attempts", "Unique IPs"],
              [(md(b["key"], 40), f"{b['doc_count']:,}", f"{b['ips']['value']:,}") for b in a["users"]["buckets"]]),
        "",
        "**Top passwords**",
        "",
        table(["Password", "Attempts"], [(md(b["key"], 40), f"{b['doc_count']:,}") for b in a["passwords"]["buckets"]]),
    ]


def section_commands(os_):
    total, a = os_.aggs({
        "cmds": terms("input", 25, aggs={"sessions": {"cardinality": {"field": "session"}},
                                         "ips": {"cardinality": {"field": "src_ip"}},
                                         "tech": terms("mitre_technique", 1)}),
        "sessions": {"cardinality": {"field": "session"}},
    }, {"term": {"eventid": "cowrie.command.input"}})
    if not total:
        return []
    return [
        f"{total:,} commands across ~{a['sessions']['value']:,} interactive sessions.",
        "",
        table(["Command", "Technique", "Times", "Sessions", "Unique IPs"],
              [(md(b["key"], 100), b["tech"]["buckets"][0]["key"] if b["tech"]["buckets"] else "",
                f"{b['doc_count']:,}", f"{b['sessions']['value']:,}", f"{b['ips']['value']:,}")
               for b in a["cmds"]["buckets"]]),
    ]


def family_label(techs: set) -> str:
    if "T1496" in techs:
        return "Cryptominer deployer"
    if "T1098.004" in techs:
        return "SSH-key persistence"
    if "T1105" in techs:
        return "Dropper / loader"
    if "T1098" in techs:
        return "Account takeover (password change)"
    if "T1053.003" in techs:
        return "Cron persistence"
    if techs and techs <= set(DISCOVERY) | {"T1059.004", "T1003.008"}:
        return "Recon / fingerprinting only"
    return "Interactive shell activity"


def section_families(os_, top_n):
    sessions = defaultdict(lambda: {"cmds": [], "techs": set(), "ip": None, "cc": None, "asn": None, "ts": None})
    for d in os_.scan(["session", "timestamp", "input", "src_ip", "geo.country_iso_code", "as.organization_name",
                       "command_techniques"], {"term": {"eventid": "cowrie.command.input"}},
                      sort=("session", "timestamp")):
        s = sessions[d.get("session")]
        s["ip"] = s["ip"] or d.get("src_ip")
        s["cc"] = s["cc"] or (d.get("geo") or {}).get("country_iso_code")
        s["asn"] = s["asn"] or (d.get("as") or {}).get("organization_name")
        s["ts"] = s["ts"] or d.get("timestamp")
        norm = normalize(d.get("input", ""))
        if norm and (not s["cmds"] or s["cmds"][-1] != norm):
            s["cmds"].append(norm)
        s["techs"].update(d.get("command_techniques") or [])
    if not sessions:
        return []

    clients = {}
    ids = list(sessions)
    for i in range(0, len(ids), 1000):
        for d in os_.scan(["session", "version"], {"term": {"eventid": "cowrie.client.version"}},
                          {"terms": {"session": ids[i:i + 1000]}}):
            clients[d["session"]] = d.get("version")

    families = defaultdict(list)
    for sid, s in sessions.items():
        sig = hashlib.sha1("\n".join(s["cmds"]).encode()).hexdigest()[:10]
        families[sig].append(sid)
    ranked = sorted(families.items(), key=lambda kv: -len(kv[1]))

    summary_rows, details = [], []
    for n, (sig, sids) in enumerate(ranked[:top_n], 1):
        members = [sessions[s] for s in sids]
        techs = set().union(*(m["techs"] for m in members))
        ips = {m["ip"] for m in members}
        ccs = Counter(m["cc"] for m in members if m["cc"]).most_common(3)
        asns = Counter(m["asn"] for m in members if m["asn"]).most_common(2)
        vers = Counter(clients.get(s) for s in sids if clients.get(s)).most_common(2)
        times = sorted(m["ts"] for m in members)
        label = family_label(techs)
        fid = f"F{n:02d}"
        summary_rows.append((fid, label, f"{len(sids):,}", f"{len(ips):,}",
                             ", ".join(f"{c} ({k})" for c, k in ccs) or "?", times[0][:10], times[-1][:10]))
        details += [
            f"#### {fid} - {label} (`{sig}`)",
            "",
            f"- Sessions: {len(sids):,} from {len(ips):,} IPs; first {times[0]}, last {times[-1]}",
            f"- Top ASNs: {', '.join(md(a, 50) + f' ({k})' for a, k in asns) or 'unknown'}",
            f"- SSH clients: {', '.join(md(v, 50) + f' ({k})' for v, k in vers) or 'unknown'}",
            f"- Techniques: {', '.join(sorted(techs)) or 'none'}",
            "",
            fenced("\n".join(members[0]["cmds"][:15]) + ("\n…" if len(members[0]["cmds"]) > 15 else "")),
            "",
        ]

    behaviours = Counter(family_label(s["techs"]) for s in sessions.values())
    enum_seqs = Counter()
    for s in sessions.values():
        ordered = [t for t in DISCOVERY if t in s["techs"]]
        if ordered:
            enum_seqs[" + ".join(ordered)] += 1
    enum_cmds = Counter()
    for s in sessions.values():
        for c in s["cmds"]:
            if re.search(r"\b(uname|lscpu|nproc|whoami|id|w|ps|ifconfig|cat /proc/\S+|free|df|ls|hostname)\b", c):
                enum_cmds[c] += 1

    lines = [
        f"{len(sessions):,} sessions ran commands; they collapse into {len(families):,} families after normalizing "
        "URLs, IPs, hashes, keys, random tokens and numbers (family = identical normalized command sequence).",
        "",
        "**Behaviour clusters (all sessions)**",
        "",
        table(["Behaviour", "Sessions"], [(k, f"{v:,}") for k, v in behaviours.most_common()]),
        "",
        f"**Top {min(top_n, len(ranked))} families**",
        "",
        table(["Family", "Behaviour", "Sessions", "Unique IPs", "Top countries", "First seen", "Last seen"], summary_rows),
        "",
        "### Enumeration patterns",
        "",
        "Which discovery techniques sessions combine (T1082 system info, T1033 user, T1057 process, "
        "T1016 network, T1083 files):",
        "",
        table(["Discovery combination", "Sessions"], [(k, f"{v:,}") for k, v in enum_seqs.most_common(10)])
        if enum_seqs else "_No discovery commands observed._",
        "",
        "Most common normalized discovery commands:",
        "",
        table(["Command (normalized)", "Sessions"], [(md(c, 100), f"{v:,}") for c, v in enum_cmds.most_common(15)])
        if enum_cmds else "_None._",
        "",
        "### Family details",
        "",
    ] + details
    return lines


def section_canary(os_):
    total, a = os_.aggs({
        "paths": terms("path", 25, aggs={"ips": {"cardinality": {"field": "src_ip"}}, "kind": terms("detection_key", 1)}),
        "uas": terms("user_agent", 20, aggs={"ips": {"cardinality": {"field": "src_ip"}}}),
        "kinds": terms("detection_key", 5),
        "methods": terms("method", 8),
    }, {"term": {"honeypot": "canary"}})
    if not total or not a["paths"]["buckets"] or not a["uas"]["buckets"]:
        return []
    return [
        f"{total:,} HTTP requests. Classification: "
        + ", ".join(f"{b['key']} {b['doc_count']:,}" for b in a["kinds"]["buckets"])
        + "; methods: " + ", ".join(f"{b['key']} {b['doc_count']:,}" for b in a["methods"]["buckets"]) + ".",
        "",
        "**Top paths**",
        "",
        table(["Path", "Class", "Requests", "Unique IPs"],
              [(md(b["key"], 90), b["kind"]["buckets"][0]["key"] if b["kind"]["buckets"] else "",
                f"{b['doc_count']:,}", f"{b['ips']['value']:,}") for b in a["paths"]["buckets"]]),
        "",
        "**Top user agents**",
        "",
        table(["User agent", "Requests", "Unique IPs"],
              [(md(b["key"], 90), f"{b['doc_count']:,}", f"{b['ips']['value']:,}") for b in a["uas"]["buckets"]]),
    ]


def main():
    parser = argparse.ArgumentParser(description="Chronos findings report (OpenSearch -> Markdown)")
    parser.add_argument("--opensearch", default=os.getenv("OPENSEARCH_HOST", "http://localhost:9200"))
    parser.add_argument("--index", default="chronos-logs-*")
    parser.add_argument("--exclude-ip", action="append", default=[],
                        help="Source IP to exclude (e.g. the analyst's own test traffic); repeatable")
    parser.add_argument("--families", type=int, default=12, help="Families to detail (default 12)")
    parser.add_argument("--output", help="Output path (default reports/findings-<UTC date>.md)")
    parser.add_argument("--allow-empty", action="store_true", help="Exit 0 even if a section has no data")
    args = parser.parse_args()

    live = not args.index.startswith("chronos-replay")
    base = [{"exists": {"field": "sensor_id"}}] if live else []
    os_ = OpenSearch(args.opensearch, args.index, base, args.exclude_ip)

    window_lines, meta = section_window(os_)
    sections = {
        "Collection window and totals": window_lines,
        "Top source countries and ASNs": section_geo(os_),
        "Attacks by MITRE technique": section_mitre(os_),
        "Top credentials tried": section_credentials(os_),
        "Top commands": section_commands(os_),
        "Bot families and enumeration patterns": section_families(os_, args.families),
        "HTTP canary paths and user agents": section_canary(os_),
    }

    now = datetime.now(timezone.utc)
    out = Path(args.output) if args.output else REPO / "reports" / f"findings-{now:%Y-%m-%d}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = [
        "# Chronos honeypot findings",
        "",
        f"Generated {now:%Y-%m-%d %H:%M} UTC from `{args.index}`"
        + (" (live sensor events only)" if live else " (synthetic replay data)")
        + (f"; excluded analyst IPs: {', '.join(args.exclude_ip)}" if args.exclude_ip else "") + ".",
        "",
        "Sensor `chronos-sensor` (AWS us-east-1, t4g.micro) exposes Cowrie SSH :22 / Telnet :23 and an HTTP canary :80. "
        "Every connection is unsolicited: nothing legitimate is hosted there.",
        "",
    ]
    empty = []
    for title in REQUIRED_SECTIONS:
        body = sections[title]
        doc += [f"## {title}", ""] + (body if body else ["_No data._"]) + [""]
        if not body:
            empty.append(title)
    out.write_text("\n".join(doc))
    print(f"[+] Wrote {out}")
    if meta:
        print(f"[*] Window {meta['first']} -> {meta['last']} ({meta['span_days']:.2f} days, "
              f"{meta['days']} non-empty days, {meta['total']:,} events)")
    if empty:
        print(f"[-] Sections without data: {', '.join(empty)}", file=sys.stderr)
        if not args.allow_empty:
            sys.exit(2)


if __name__ == "__main__":
    main()
