#!/usr/bin/env python3
"""tier_audit.py — measure how classify() buckets the currently active hosts.

Aggregates one record per IP from current_state (active = seen in the last N
days), runs triage_report.classify() over each, and prints the tier
distribution, the top orgs per priority tier, and the reasons that put them
there. Use it before and after changing the classifier. Read-only.

    venv/bin/python tier_audit.py            # summary
    venv/bin/python tier_audit.py --examples # plus concrete misfire examples
    venv/bin/python tier_audit.py --compare old_triage_report.py
"""
import argparse
import collections
import importlib.util
import os
import sys

import duckdb

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import triage_report as tr  # noqa: E402

Q = """
select ip, any_value(org), list(distinct port),
       string_agg(distinct hostnames, ','), string_agg(distinct domains, ','),
       string_agg(distinct tags, ',')
from current_state
where date >= (select max(date) from observations) - interval {days} day
group by ip
"""


def load_hosts(days):
    con = duckdb.connect(os.path.join(SCRIPT_DIR, "store", "exposure.duckdb"), read_only=True)
    hosts = {}
    for ip, org, ports, hn, dm, tg in con.execute(Q.format(days=days)).fetchall():
        hosts[ip] = {"org": org, "ports": set(ports),
                     "hostnames": sorted({h for h in (hn or "").split(",") if h}),
                     "domains": sorted({d for d in (dm or "").split(",") if d}),
                     "tags": {t for t in (tg or "").split(",") if t}}
    return hosts


def load_module(path):
    spec = importlib.util.spec_from_file_location("old_tr", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def summarize(classify, hosts, label):
    tiers = collections.Counter()
    by_org = collections.defaultdict(collections.Counter)
    reasons = collections.defaultdict(collections.Counter)
    for h in hosts.values():
        t, r = classify(h)
        tiers[t] += 1
        by_org[t][h["org"]] += 1
        reasons[t][r.split(" (")[0]] += 1
    print(f"\n===== {label}: {len(hosts)} active hosts")
    for t, n in tiers.most_common():
        print(f"  {t:26} {n:7,}")
    for t in ("critical_infrastructure", "government", "education", "honeypot", "out_of_state_gov"):
        if not by_org.get(t):
            continue
        print(f"\n  -- {t}: top orgs")
        for o, n in by_org[t].most_common(12):
            print(f"     {n:6,}  {o}")
        print("     reasons:", ", ".join(f"{r}={n}" for r, n in reasons[t].most_common(8)))
    return tiers


def examples(hosts):
    def ex(pred, n=4):
        out = []
        for h in hosts.values():
            if pred(h):
                out.append((h["org"], h["hostnames"][:2], h["domains"][:2],
                            sorted(h["ports"])[:5], sorted(h["tags"])[:3]))
            if len(out) >= n:
                break
        return out
    cases = [
        ("Cameron gov", lambda h: (h["org"] or "").startswith("Cameron Communications") and tr.classify(h)[0] == "government"),
        ("Allens gov", lambda h: (h["org"] or "").startswith("Allens") and tr.classify(h)[0] == "government"),
        ("PA gov", lambda h: "Commonwealth of PA" in (h["org"] or "")),
        ("REV edu", lambda h: (h["org"] or "") == "REV" and tr.classify(h)[0] == "education"),
        ("Whole Sale edu", lambda h: (h["org"] or "") == "Whole Sale" and tr.classify(h)[0] == "education"),
        ("LIGO", lambda h: "LIGO" in (h["org"] or "")),
        ("Pavlov", lambda h: "PAVLOV" in (h["org"] or "").upper() and tr.classify(h)[0] == "government"),
        ("Loyola", lambda h: "Loyola" in (h["org"] or "")),
        ("UL Lafayette", lambda h: "University of Louisiana at Lafayette" in (h["org"] or "")),
        ("honeypot-tag crit", lambda h: "honeypot" in h["tags"] and tr.classify(h)[0] == "critical_infrastructure"),
        ("megaport crit", lambda h: len(h["ports"]) > 100 and tr.classify(h)[0] == "critical_infrastructure"),
        ("k12", lambda h: any(d.endswith("k12.la.us") for d in h["domains"])),
        ("la.gov", lambda h: any(d.endswith("la.gov") for d in h["domains"])),
        ("Verizon crit", lambda h: (h["org"] or "").startswith("Verizon") and tr.classify(h)[0] == "critical_infrastructure"),
        ("Cox crit", lambda h: (h["org"] or "").startswith("Cox") and tr.classify(h)[0] == "critical_infrastructure"),
        ("Acadiana Wireless", lambda h: "ACADIANA WIRELESS" in (h["org"] or "").upper()),
        ("Parish Broadband", lambda h: "Parish Broadband" in (h["org"] or "")),
    ]
    print("\n===== EXAMPLES (org, hostnames, domains, ports, tags)")
    for label, pred in cases:
        print(f"\n-- {label}")
        for e in ex(pred):
            print("   ", e)
    govs = sorted({d for h in hosts.values() for d in h["domains"]
                   if d.endswith(".gov") and not d.endswith("la.gov")})
    print("\n.gov domains that are not la.gov:", govs[:40])
    print("orgs containing 'revenue':", [o for o in {h["org"] for h in hosts.values()} if o and "revenue" in o.lower()][:5])
    print("orgs containing a parish name as a word, top 25:")
    import re
    c = collections.Counter()
    for h in hosts.values():
        o = (h["org"] or "").lower()
        for par in tr.PARISHES:
            if re.search(r"\b" + re.escape(par) + r"\b", o):
                c[h["org"]] += 1
    for o, n in c.most_common(25):
        print(f"   {n:6,}  {o}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=45)
    ap.add_argument("--examples", action="store_true")
    ap.add_argument("--compare", help="path to a previous triage_report.py to diff against")
    args = ap.parse_args()
    hosts = load_hosts(args.days)
    new = summarize(tr.classify, hosts, "CURRENT triage_report.classify")
    if args.compare:
        old = summarize(load_module(args.compare).classify, hosts, f"OLD {args.compare}")
        print("\n===== DELTA (new - old)")
        for t in sorted(set(new) | set(old)):
            print(f"  {t:26} {new.get(t, 0) - old.get(t, 0):+8,}")
    if args.examples:
        examples(hosts)


if __name__ == "__main__":
    main()
