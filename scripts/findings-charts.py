#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib>=3.8"]
# ///
"""
findings-charts.py - Chronos findings charts (OpenSearch -> PNG).

Companion to findings-report.py: same index, same live-data filter, same --exclude-ip handling (it reuses that
script's OpenSearch client). Writes reports/charts/*.png:

  daily-volume.png        events and unique source IPs per UTC day
  countries.png           top countries by unique IPs next to their event volume
  mitre-techniques.png    events per primary MITRE ATT&CK technique, coloured by tactic
  credentials.png         most tried username/password pairs
  honeytoken-timeline.png .env bait fetches vs CloudTrail key use, with the window CloudTrail could see
  honeytoken-latency.png  delay between a .env fetch and the next use of its key
  honeytoken-api-calls.png AWS API calls attempted with the bait keys

Run with uv (pulls matplotlib into a throwaway env) through the SSM tunnel to :9200:
  uv run scripts/findings-charts.py --exclude-ip <your-public-ip>
"""
import argparse
import importlib.util
import os
import textwrap
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("findings_report", REPO / "scripts" / "findings-report.py")
fr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fr)

INK, MUTED, GRID = "#1f2328", "#656d76", "#d0d7de"
BLUE, ORANGE, RED, GREEN, PURPLE, GREY = "#0969da", "#d4700b", "#cf222e", "#1a7f37", "#8250df", "#8c959f"
TACTIC_COLOURS = {"Execution": BLUE, "Reconnaissance": GREEN, "Initial Access": RED, "Command and Control": PURPLE,
                  "Credential Access": ORANGE}
# Delay (seconds) from a .env fetch to the next burst of AWS calls with its key; slower than the last bucket
# counts as not tried.
LATENCY_BUCKETS = [(0, "0 s"), (1, "1 s"), (2, "2 s"), (10, "3-10 s"), (180, "11 s-3 min")]
NOT_TRIED = "> 3 min / never"

plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white", "savefig.facecolor": "white",
    "font.size": 11, "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
    "axes.edgecolor": GRID, "axes.labelcolor": MUTED, "text.color": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
})
thousands = FuncFormatter(lambda v, _: f"{v:,.0f}")


def save(fig, out_dir, name, title, sub, source):
    """Figure-level title + wrapped subtitle (aligned to the figure, not the axes), footer, then lay out below."""
    height = fig.get_size_inches()[1]
    lines = textwrap.wrap(sub, 120)
    fig.text(0.01, 1 - 0.22 / height, title, fontsize=15, fontweight="bold", color=INK, va="top")
    fig.text(0.01, 1 - 0.58 / height, "\n".join(lines), fontsize=10.5, color=MUTED, va="top", linespacing=1.35)
    fig.text(0.01, 0.01, f"Project Chronos honeypot, AWS us-east-1 · {source}", color=MUTED, fontsize=8.5,
             ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.35 / height, 1, 1 - (0.78 + 0.2 * len(lines)) / height))
    path = out_dir / name
    fig.savefig(path, dpi=200)
    plt.close(fig)
    print(f"[+] {path.relative_to(REPO) if path.is_relative_to(REPO) else path}")


def parse(ts):
    return fr.parse_time(ts)


def chart_daily(os_, out, window):
    _, a = os_.aggs({"daily": {"date_histogram": {"field": "timestamp", "calendar_interval": "1d", "min_doc_count": 0},
                               "aggs": {"ips": {"cardinality": {"field": "src_ip"}},
                                        "top": fr.terms("src_ip", 1)}}})
    days = a["daily"]["buckets"]
    x = [parse(b["key_as_string"]) for b in days]
    events = [b["doc_count"] for b in days]
    ips = [b["ips"]["value"] for b in days]

    fig, ax = plt.subplots(figsize=(11, 5.6))
    ax.bar(x, events, width=0.75, color=BLUE, alpha=0.85, label="Events")
    ax.yaxis.set_major_formatter(thousands)
    ax.set_ylabel("Events per day")
    ax2 = ax.twinx()
    ax2.plot(x, ips, color=ORANGE, marker="o", lw=2, label="Unique source IPs")
    ax2.set_ylim(0, max(ips) * 1.35)
    ax2.set_ylabel("Unique source IPs", color=ORANGE)
    ax2.tick_params(axis="y", colors=ORANGE)
    ax2.grid(False)
    ax2.spines["right"].set_visible(True)

    peak = max(range(len(days)), key=lambda i: events[i])
    top = days[peak]["top"]["buckets"][0]
    ax.annotate(f"{events[peak]:,} events: one IP ({top['key']})\nsent {top['doc_count']:,} of them",
                xy=(x[peak], events[peak]), xytext=(x[peak] - timedelta(days=6.2), events[peak] * 0.9),
                fontsize=9.5, color=INK, arrowprops={"arrowstyle": "->", "color": MUTED})
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper left", frameon=False)
    save(fig, out, "daily-volume.png", "Seventeen days on the open internet",
         f"{window['total']:,} events from ~{window['ips']:,} source IPs. The number of bots per day is steady; "
         "the volume comes from a handful of very loud ones.", "events per UTC day")


def chart_countries(os_, out):
    _, a = os_.aggs({"c": fr.terms("geo.country_name", 40, aggs={"ips": {"cardinality": {"field": "src_ip"}}})})
    rows = sorted(a["c"]["buckets"], key=lambda b: -b["ips"]["value"])[:12][::-1]
    names = [b["key"] for b in rows]

    fig, (left, right) = plt.subplots(1, 2, figsize=(11, 6), sharey=True)
    left.barh(names, [b["ips"]["value"] for b in rows], color=BLUE)
    left.set_title("Unique source IPs", fontsize=12, pad=8)
    left.xaxis.set_major_formatter(thousands)
    right.barh(names, [b["doc_count"] for b in rows], color=ORANGE)
    right.set_title("Events", fontsize=12, pad=8)
    right.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:,.0f}k"))
    for ax in (left, right):
        ax.grid(axis="y", visible=False)
        ax.tick_params(axis="y", length=0)
    save(fig, out, "countries.png", "Who knocks vs who is loud",
         "Countries ranked by unique attacking IPs. A few dozen Pakistani IPs out-shout hundreds of US ones.",
         "GeoIP: GeoLite2 bundled with OpenSearch 2.11.1")


def chart_mitre(os_, out):
    _, a = os_.aggs({"t": fr.terms("mitre_technique", 20, aggs={"tactic": fr.terms("mitre_tactic", 1),
                                                                "ips": {"cardinality": {"field": "src_ip"}}})})
    rows = [b for b in a["t"]["buckets"] if b["key"] != "None"][:14][::-1]
    labels = [f"{b['key']}  {fr.TECHNIQUE_NAMES.get(b['key']) or ('Valid Accounts: Cloud' if b['key'] == 'T1078.004' else '')}"
              for b in rows]
    tactics = [b["tactic"]["buckets"][0]["key"] if b["tactic"]["buckets"] else "" for b in rows]
    fig, ax = plt.subplots(figsize=(11, 6.4))
    bars = ax.barh(labels, [b["doc_count"] for b in rows], color=[TACTIC_COLOURS.get(t, GREY) for t in tactics])
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(thousands)
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    for bar, b in zip(bars, rows):
        ax.text(bar.get_width() * 1.08, bar.get_y() + bar.get_height() / 2,
                f"{b['doc_count']:,}  ·  {b['ips']['value']:,} IPs", va="center", fontsize=9, color=MUTED)
    ax.set_xlim(right=max(b["doc_count"] for b in rows) * 12)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for t, c in TACTIC_COLOURS.items() if t in tactics]
    ax.legend(handles, [t for t in TACTIC_COLOURS if t in tactics], loc="lower right", frameon=False, fontsize=9.5)
    save(fig, out, "mitre-techniques.png", "What they did once inside (MITRE ATT&CK)",
         "Primary technique per event, log scale. Shell commands dominate; cloud-key abuse (T1078.004) is rare "
         "but the most valuable signal.", "Vector catalog + command rules")


def chart_credentials(os_, out):
    total, a = os_.aggs({"pairs": {"multi_terms": {"terms": [{"field": "username"}, {"field": "password"}], "size": 15},
                                   "aggs": {"ips": {"cardinality": {"field": "src_ip"}}}}},
                        {"terms": {"eventid": ["cowrie.login.failed", "cowrie.login.success"]}})
    rows = a["pairs"]["buckets"][::-1]

    def show(s):
        s = s.replace("\x00", "\\0")
        return s if s else "(empty)"

    labels = [f"{show(b['key'][0])} / {show(b['key'][1])}" for b in rows]
    fig, ax = plt.subplots(figsize=(11, 6.4))
    bars = ax.barh(labels, [b["doc_count"] for b in rows], color=[RED if i == len(rows) - 1 else BLUE
                                                                 for i in range(len(rows))])
    for bar, b in zip(bars, rows):
        ax.text(bar.get_width() + total * 0.002, bar.get_y() + bar.get_height() / 2,
                f"{b['doc_count']:,}  ·  {b['ips']['value']:,} IPs", va="center", fontsize=9, color=MUTED)
    ax.set_xlim(right=rows[-1]["doc_count"] * 1.22)
    ax.xaxis.set_major_formatter(thousands)
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    for t in ax.get_yticklabels():
        t.set_fontfamily("monospace")
    save(fig, out, "credentials.png", "admin / admin is still the master key",
         f"Top 15 of {total:,} SSH/Telnet login attempts (username / password). xc3511, vizxv, juantech and anko "
         "come from Mirai's factory-default list.", "Cowrie login events")


def honeytoken_data(os_):
    fetches = [(parse(d["timestamp"]), d) for d in os_.scan(
        ["timestamp", "src_ip", "bait", "as.organization_name"],
        {"term": {"honeypot": "canary"}}, {"term": {"honeytoken_served": True}}, {"term": {"bait": "dotenv"}})]
    uses = [(parse(d["timestamp"]), d) for d in os_.scan(
        ["timestamp", "bait", "src_ip", "source_address", "aws_event_source", "aws_event_name", "aws_region",
         "aws_error_code"],
        {"term": {"honeypot": "honeytoken"}})]
    return fetches, uses


def bursts_of(uses, gap=600):
    """Consecutive key uses from one source within `gap` seconds form one validation burst."""
    out = []
    for t, u in uses:
        src = u.get("src_ip") or u.get("source_address")
        if out and out[-1]["src"] == src and (t - out[-1]["end"]).total_seconds() < gap:
            out[-1]["end"] = t
            out[-1]["n"] += 1
        else:
            out.append({"src": src, "start": t, "end": t, "n": 1})
    return out


def chart_honeytokens(os_, out, visible_until):
    fetches, uses = honeytoken_data(os_)
    if not uses:
        print("[!] no honeytoken key use; skipping honeytoken charts")
        return
    bursts = bursts_of([(t, u) for t, u in uses if u.get("bait") == "dotenv"])
    starts = [b["start"] for b in bursts]

    # --- timeline -------------------------------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(11, 5))
    ft = [t for t, _ in fetches]
    ax.scatter(ft, [1] * len(ft), marker="|", s=420, color=BLUE, lw=1.4, label=f".env fetched ({len(ft)})")
    ax.scatter(starts, [0] * len(starts), marker="|", s=420, color=RED, lw=1.4,
               label=f"key tried against AWS ({len(uses)} calls in {len(bursts)} bursts)")
    end = max(ft[-1], visible_until) + timedelta(hours=6)
    ax.axvspan(visible_until, end, color=GREY, alpha=0.18, lw=0)
    after = sum(1 for t in ft if t >= visible_until)
    ax.text(visible_until + timedelta(hours=4), 0.5,
            f"Honeytoken AWS account suspended:\nCloudTrail no longer visible.\n{after} more fetches,\nkey use unknown.",
            va="center", fontsize=10, color=INK)
    ax.set_yticks([0, 1], ["key used", "bait fetched"])
    ax.set_ylim(-0.7, 1.7)
    ax.set_xlim(ft[0] - timedelta(hours=6), end)
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
    ax.legend(loc="upper left", bbox_to_anchor=(0, -0.1), ncol=2, frameon=False)
    save(fig, out, "honeytoken-timeline.png", "A planted AWS key is tried within seconds, all day long",
         "Each tick is one request for /.env (top) or the start of an AWS API burst with its key (bottom).",
         "canary bait fetches + honeytoken account CloudTrail")

    # --- latency --------------------------------------------------------------------------------------------
    seen = [(t, f) for t, f in fetches if t < visible_until]
    counts = Counter()
    for t, _ in seen:
        delays = [(s - t).total_seconds() for s in starts if (s - t).total_seconds() >= 0]
        d = min(delays) if delays else None
        label = next((name for limit, name in LATENCY_BUCKETS if d is not None and d <= limit), NOT_TRIED)
        counts[label] += 1
    labels = [name for _, name in LATENCY_BUCKETS] + [NOT_TRIED]
    vals = [counts[name] for name in labels]
    fast = sum(vals[:3])
    fig, ax = plt.subplots(figsize=(11, 5.2))
    bars = ax.bar(labels, vals, color=[RED, RED, RED, ORANGE, ORANGE, GREY])
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.6, f"{v}\n({v / len(seen):.0%})", ha="center", va="bottom",
                fontsize=10)
    ax.set_ylim(0, max(vals) * 1.3)
    ax.grid(axis="x", visible=False)
    ax.set_ylabel(".env fetches")
    save(fig, out, "honeytoken-latency.png", f"{fast / len(seen):.0%} of .env fetches were followed by a key test "
         "within 2 seconds",
         f"Delay from each of the {len(seen)} .env fetches made while CloudTrail was visible to the next AWS call "
         "with that key. The fetching IP and the testing IP were almost never the same.",
         "canary bait fetches + honeytoken account CloudTrail")

    # --- API calls ------------------------------------------------------------------------------------------
    calls = Counter(f"{(u.get('aws_event_source') or '').split('.')[0]}:{u.get('aws_event_name')}"
                    for _, u in uses)
    allowed = Counter(f"{(u.get('aws_event_source') or '').split('.')[0]}:{u.get('aws_event_name')}"
                      for _, u in uses if not u.get("aws_error_code"))
    rows = calls.most_common()[::-1]
    fig, ax = plt.subplots(figsize=(11, 4.8))
    bars = ax.barh([k for k, _ in rows], [v for _, v in rows],
                   color=[GREEN if allowed[k] else RED for k, _ in rows])
    for bar, (k, v) in zip(bars, rows):
        ax.text(bar.get_width() + 6, bar.get_y() + bar.get_height() / 2,
                f"{v:,}  ({'allowed: identity only' if allowed[k] else 'denied'})", va="center", fontsize=9.5,
                color=MUTED)
    ax.set_xlim(right=rows[-1][1] * 1.35)
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    for t in ax.get_yticklabels():
        t.set_fontfamily("monospace")
    ses_regions = len({u.get("aws_region") for _, u in uses if u.get("aws_event_source") == "ses.amazonaws.com"})
    save(fig, out, "honeytoken-api-calls.png", "They wanted your email quota, not your data",
         f"AWS API calls made with the bait keys: SES sender checks across {ses_regions} regions, SMS limits, then an "
         "IAM user for persistence. A spam-relay checklist.", "honeytoken account CloudTrail")


def main():
    parser = argparse.ArgumentParser(description="Chronos findings charts (OpenSearch -> PNG)")
    parser.add_argument("--opensearch", default=os.getenv("OPENSEARCH_HOST", "http://localhost:9200"))
    parser.add_argument("--index", default="chronos-logs-*")
    parser.add_argument("--exclude-ip", action="append", default=[],
                        help="Source IP to exclude (e.g. the analyst's own test traffic); repeatable")
    parser.add_argument("--honeytoken-visible-until",
                        help="UTC time CloudTrail key-use visibility ended (default: last key-use event)")
    parser.add_argument("--output-dir", default=str(REPO / "reports" / "charts"))
    args = parser.parse_args()

    os_ = fr.OpenSearch(args.opensearch, args.index, [{"exists": {"field": "sensor_id"}}], args.exclude_ip)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    total, w = os_.aggs({"ips": {"cardinality": {"field": "src_ip"}},
                         "last_use": {"filter": {"term": {"honeypot": "honeytoken"}},
                                      "aggs": {"t": {"max": {"field": "timestamp"}}}}})
    visible_until = (datetime.fromisoformat(args.honeytoken_visible_until).replace(tzinfo=timezone.utc)
                     if args.honeytoken_visible_until else
                     parse(w["last_use"]["t"]["value_as_string"]) if w["last_use"]["doc_count"] else None)

    chart_daily(os_, out, {"total": total, "ips": w["ips"]["value"]})
    chart_countries(os_, out)
    chart_mitre(os_, out)
    chart_credentials(os_, out)
    if visible_until:
        chart_honeytokens(os_, out, visible_until)


if __name__ == "__main__":
    main()
