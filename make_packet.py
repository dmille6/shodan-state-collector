#!/usr/bin/env python3
"""
make_packet.py — build a sendable notification packet for ONE organisation from
the leads table, the current store and the registry.

Generalises reports/Fletcher_Compromise_Notification_2026-07-08.md and
scripts/build_ochsner_report.py: evidence first, then exactly what the finding is
NOT (passive, unverified, no access to any system), then prioritised actions and
how the owner can verify for themselves. No organisation is hard-coded.

    make_packet.py --org "Nicholls State University"       # org_name or org_id
    make_packet.py --ip 203.0.113.10                        # everything on one host
    make_packet.py --org ... --include-closed               # also remediated/disputed/fp/suppressed
    make_packet.py --org ... --pdf                          # + PDF (reportlab)
    make_packet.py --org ... --dry-run                      # print, write nothing

Rules
- Only leads in status new/queued by default, plus notified/acknowledged marked
  "previously notified on <date>"; closed statuses only with --include-closed.
- Refused: ineligible leads, leads flagged needs_attribution_review (clear with
  `leads.py set <id> --review-cleared`), and leads whose host's CURRENT tier in
  latest_observed is residential/honeypot — all re-checked here, independently
  of leads.py.
- The selected leads must attribute to ONE organisation or the packet is refused
  with the list. Lead rows for one ip are ordered by last_evaluated; if they
  disagree on org the address is flagged as an attribution conflict.
- Per lead the packet states whether the service is currently active, stale or
  gone ("last observed <date>"); new/queued leads whose service is gone go under
  "no longer observed — historical".
- Appendix (cross-tenant safety): other services on an address are listed ONLY
  when the CURRENT registry generation (looked up at packet time, never from
  historical lead rows) records whole-address ownership for the recipient
  (ots_cidr / registry_network, high confidence, no conflict); otherwise only the
  lead services themselves, with "other services on this address omitted".
- Refused as well: leads carrying a registry attr_conflict (until cleared).
- Host-level leads (compromise flags, sinkhole hits) are "currently observed"
  only while their last event is within 30 days; older ones are historical.
- Attribution is stated as recorded (registry method/confidence; Shodan org shown
  as a low-confidence label; else "unattributed"). Every external string is
  escaped at every rendering boundary. The packet is DRAFT until signed off; a
  compromise claim requires a second reviewer.

Output: reports/packets/<org-slug>_<date>.md (+ .pdf).
"""
import argparse
import ipaddress
import os
import re
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import leads as L   # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PACKET_DIR = os.path.join(SCRIPT_DIR, "reports", "packets")

TLP_PLACEHOLDER = "[TLP:AMBER — confirm marking before release]"
UNIT_PLACEHOLDER = "[ISSUING UNIT — e.g. Louisiana State Police Cyber Crime Unit; analyst name, phone, email]"
OPEN_STATUSES = ("new", "queued", "notified", "acknowledged")
PREVIOUSLY_NOTIFIED = ("notified", "acknowledged")

EVIDENCE_LABEL = {
    "kev_verified": "Known-exploited vulnerability — VERIFIED by the scanner",
    "kev_inferred": "Known-exploited vulnerability — inferred from banner version (unverified)",
    "compromise_tag": "Possible compromise — scanner threat flag",
    "shadowserver_compromise": "Possible infection — Shadowserver sinkhole / abuse report",
    "shadowserver_exposure": "Exposed or vulnerable service — Shadowserver scan report",
    "ics": "Industrial control protocol reachable from the internet",
    "appliance": "Internet-edge appliance exposed (management / VPN portal)",
    "ioc_match": "IP address listed by a threat-intelligence feed",
    "cred_leak": "Credential exposure",
}
COMPROMISE_KINDS = {"compromise_tag", "shadowserver_compromise"}
KIND_ORDER = ["compromise_tag", "shadowserver_compromise", "kev_verified", "ics", "appliance",
              "shadowserver_exposure", "kev_inferred", "ioc_match", "cred_leak"]

ACTIONS = {
    "compromise_tag": [
        "Treat the host as potentially compromised until an investigation proves otherwise: isolate it from "
        "the network (do not power it off) and preserve logs, memory and disk before rebuilding.",
        "Review the listed service and host for unexpected accounts, scheduled tasks, outbound connections and "
        "recently installed software; check adjacent systems the host can reach.",
    ],
    "shadowserver_compromise": [
        "Shadowserver observed this address contacting a malware sinkhole or otherwise behaving as an infected "
        "host at the stated time. Correlate the timestamp with your firewall / proxy / DNS / NAT / DHCP logs to "
        "identify the internal device, then examine that device for malware.",
        "Preserve logs for the reported window before they roll over; the report names the time and the "
        "infection family (tag) — not an exposed service.",
    ],
    "shadowserver_exposure": [
        "Shadowserver's scan found the listed service reachable (and, where stated, vulnerable or misconfigured). "
        "Confirm whether it is meant to be internet-facing; restrict it or patch it per the report type.",
    ],
    "kev_verified": [
        "Patch or take offline immediately: the CVE is on CISA's Known Exploited Vulnerabilities list and the "
        "scanner reports confirming it on this host — assume it has been attempted.",
        "After patching, check the host for signs of prior exploitation (web shells, new accounts, odd processes).",
    ],
    "kev_inferred": [
        "Confirm the actual software version on the host; if it is within the affected range for the listed "
        "CVE, patch on the vendor's emergency timeline (CISA KEV = exploited in the wild).",
    ],
    "appliance": [
        "Confirm the appliance firmware is current against the vendor's security advisories and CISA KEV; these "
        "product families are targeted for mass exploitation within days of a disclosure.",
        "Restrict the management interface to trusted networks or a VPN with MFA; expose only the user-facing "
        "portal if it must be public.",
    ],
    "ics": [
        "Verify whether the listed industrial protocol is genuinely reachable from the internet and whether that "
        "is intended. ICS protocols typically have no authentication; reachability alone is a serious exposure "
        "that must be verified, and is normally removed with a firewall rule, VPN or vendor remote-access gateway.",
        "If it is reachable, check the device for unexpected writes: controller run/stop state, program "
        "checksums and recent configuration changes.",
    ],
    "ioc_match": [
        "Check the host for malware and for outbound traffic to the listed feed's indicators; confirm the "
        "address is yours (shared / NAT addresses are common).",
    ],
    "cred_leak": ["Reset the exposed credentials and review for use since the exposure date."],
}
VERIFY = {
    "kev_verified": "Read the installed version on the host and compare with the CVE's affected range. The "
                    "scanner's `verified` flag means it confirmed the vulnerability's behaviour, not just the version.",
    "kev_inferred": "Read the installed version / patch level on the host itself. Banners lag patches — an "
                    "already-patched host can still advertise a vulnerable-looking version.",
    "compromise_tag": "Compare the flagged banner (below) against the host; look for the artefact named in the "
                      "tag. Threat tags can be stale (a cached scan) or a false positive — the date of the "
                      "flagged banner is given.",
    "shadowserver_compromise": "The event names the exact UTC time and the infection family observed. Match it "
                               "to your NAT / DHCP / proxy logs for that minute to find the internal device.",
    "shadowserver_exposure": "The event names the address, port and report type; confirm the service from "
                             "outside your network or from the firewall rule that exposes it.",
    "ics": "From outside your network (e.g. a phone hotspot) attempt to connect to the listed port with the "
           "vendor's client — or simply confirm the firewall rule that exposes it.",
    "appliance": "Open the listed address in a browser from outside your network and confirm the product / "
                 "login page; read the firmware version from the appliance console.",
    "ioc_match": "Confirm the address belongs to you (ARIN / your ISP) and check the feed's listing reason "
                 "for the listed date.",
    "cred_leak": "Check the account named in the evidence for the listed credential.",
}

_ESC_RE = re.compile(r"([\\`*_\[\]|<>#~])")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_HEX_RE = re.compile(r"^[0-9a-f]{16}$")


def esc(s, limit=200):
    """Escape untrusted text for markdown prose / table cells."""
    if s is None:
        return ""
    t = _ESC_RE.sub(r"\\\1", _CTRL_RE.sub(" ", str(s)))
    return t[:limit] + ("…" if len(t) > limit else "")


def code(s, limit=200):
    """Escape untrusted text for a backtick code span (inside a table cell too)."""
    if s is None:
        return ""
    t = _CTRL_RE.sub(" ", str(s)).replace("`", "'").replace("|", "\\|")
    return t[:limit] + ("…" if len(t) > limit else "")


def ipc(s):
    """An address is rendered raw only when it IS an address."""
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        return code(s, 60)


def tp(s):
    return L.norm_transport(s)


def num(s):
    try:
        return str(int(s))
    except (TypeError, ValueError):
        return esc(s, 20)


def dt(s):
    return esc(str(s)[:19] if s is not None else "n/a", 19)


def lid(s):
    return s if isinstance(s, str) and _HEX_RE.match(s) else code(s, 16)


def status_word(s):
    return s if s in L.STATUSES else esc(s, 20)


def slugify(s):
    s = re.sub(r"[^A-Za-z0-9]+", "_", s or "org").strip("_")
    return (s or "org")[:60]


def kind_of(lead):
    if lead["evidence_type"] == "shadowserver":
        return "shadowserver_compromise" if str(lead.get("evidence_key") or "").startswith("compromise") \
            else "shadowserver_exposure"
    return lead["evidence_type"] if lead["evidence_type"] in EVIDENCE_LABEL else "cred_leak"


def org_key(lead):
    return (lead.get("org_id") or "").strip().lower() or f"name:{(lead.get('org_name') or '').strip().lower()}"


def days_ago(d, today):
    d = L._parse_date(d)
    return None if d is None else (today - d).days


def current_host_tiers(con, ips):
    if not ips:
        return {}
    ph = ", ".join("?" * len(ips))
    rows = L.fetch_dicts(con, f"""
        SELECT ip, tier FROM (SELECT ip, tier, row_number() OVER (PARTITION BY ip ORDER BY date DESC,
               banner_ts DESC NULLS LAST, observation_id DESC) AS rn FROM store.latest_observed WHERE ip IN ({ph}))
        WHERE rn = 1""", ips)
    return {r["ip"]: r["tier"] for r in rows}


def select_leads(ctx, org=None, ip=None, include_closed=False):
    statuses = None if include_closed else OPEN_STATUSES
    if ip:
        rows = L.ranked_leads(ctx, ip=ip, statuses=statuses)
    else:
        if org.strip().lower() == L.UNATTRIBUTED:
            raise SystemExit("ERROR: 'unattributed' is not an organisation; pick a host with --ip")
        rows = L.ranked_leads(ctx, org=org, statuses=statuses)
        if not rows:
            import triage_report as tr
            every = L.ranked_leads(ctx, statuses=statuses)
            rows = [r for r in every if r.get("org_name") and r["org_name"] != L.UNATTRIBUTED
                    and tr.kw_in(org.lower(), r["org_name"].lower())]
            names = sorted({r["org_name"] for r in rows})
            if len(names) > 1:
                raise SystemExit("ERROR: --org matches several organisations; be exact:\n  " + "\n  ".join(names))
    refused = []
    tiers = current_host_tiers(ctx.con, sorted({r["ip"] for r in rows}))
    kept = []
    for r in rows:
        cur = tiers.get(r["ip"])
        if (r.get("tier") or "") in L.NEVER_LEAD_TIERS or cur in L.NEVER_LEAD_TIERS:
            refused.append(f"{r['lead_id']} host is {cur or r.get('tier')} now — not a notification target")
        elif not r.get("eligible", True):
            refused.append(f"{r['lead_id']} ineligible: {r.get('eligibility_reason')}")
        elif r.get("needs_attribution_review"):
            refused.append(f"{r['lead_id']} needs attribution review"
                           + (f" (registry conflict: {esc(r.get('attr_conflict'), 80)})" if (r.get("attr_conflict") or "").strip() else "")
                           + f" — `leads.py set {r['lead_id']} --review-cleared`")
        else:
            kept.append(r)
    for msg in refused:
        L.log("refused " + msg)
    if not kept:
        raise SystemExit(f"No packet for {org or ip!r}: no eligible open lead (statuses {', '.join(statuses or ['any'])})"
                         + (f"; {len(refused)} refused, see above" if refused else "") + ".")
    orgs = {}
    for r in kept:
        orgs.setdefault(org_key(r), r.get("org_name") or L.UNATTRIBUTED)
    if len(orgs) > 1:
        raise SystemExit("ERROR: the selected leads attribute to more than one organisation — one packet per org:\n  "
                         + "\n  ".join(sorted(set(orgs.values()))))
    return kept


def whole_address_ips(reg, ips, okey):
    """Addresses the CURRENT registry generation records as wholly owned by the
    packet's org: ots_cidr / registry_network, high confidence, no conflict."""
    out = set()
    if not reg.available:
        return out
    for ip in ips:
        hit = reg.lookup(ip)
        if not hit or hit.get("method") not in L.WHOLE_ADDRESS_METHODS or (hit.get("confidence") or "") != "high":
            continue
        if (hit.get("conflict") or "").strip():
            continue
        hkey = (hit.get("org_id") or "").strip().lower() or f"name:{(hit.get('org_name') or '').strip().lower()}"
        if hkey == okey:
            out.add(ip)
    return out


def gather(ctx, today, org=None, ip=None, include_closed=False, registry_dir=L.REGISTRY_DIR):
    con = ctx.con
    leads = select_leads(ctx, org, ip, include_closed)
    name = leads[0].get("org_name") or L.UNATTRIBUTED
    okey = org_key(leads[0])
    ips = sorted({l["ip"] for l in leads})
    ph = ", ".join("?" * len(ips))
    # Per-ip attribution from EVERY lead row on the address, ordered by last_evaluated
    # (newest last); a disagreement is a conflict, never "the last row wins".
    ip_orgs = {}
    for r in L.fetch_dicts(con, f"SELECT ip, org_id, org_name, last_evaluated, lead_id FROM leads WHERE ip IN ({ph}) "
                                f"ORDER BY last_evaluated, lead_id", ips):
        ip_orgs.setdefault(r["ip"], []).append(org_key(r))
    conflicts = {ip for ip, ks in ip_orgs.items() if len(set(ks)) > 1}
    # Appendix authorization comes from the CURRENT registry, never from lead rows.
    whole = whole_address_ips(L.Registry(registry_dir), ips, okey) - conflicts
    wanted = ["ip", "port", "transport", "date", "status", "days_since_seen", "org", "product", "version", "service",
              "cpe23", "http_title", "hostnames", "banner_ts", "cert_cn", "cert_org", "cert_issuer", "cert_sans", "tier"]
    services = {}
    for r in L.fetch_dicts(con, f"SELECT {L._adaptive_cols(con, 'exposure_status', wanted)} FROM store.exposure_status "
                                f"WHERE ip IN ({ph})", ips):
        services[(r["ip"], r["port"], r["transport"])] = r
    lead_keys = {(l["ip"], l["port"], l["transport"]) for l in leads}
    appendix = {k: r for k, r in services.items()
                if (k[0] in whole and r["status"] == "active") or (k in lead_keys)}
    omitted = sorted(ip for ip in ips if ip not in whole)
    cves = {}
    for r in L.fetch_dicts(con, f"""
            SELECT lo.ip, lo.port, lo.transport, v.cve, v.cvss, v.epss, v.verified
            FROM store.latest_observed lo JOIN store.vulns v ON v.observation_id = lo.observation_id AND v.date = lo.date
            WHERE lo.ip IN ({ph}) AND v.in_kev""", ips):
        cves.setdefault((r["ip"], r["port"], r["transport"]), []).append(r)
    life = {(r["ip"], r["port"], r["transport"]): r for r in
            L.fetch_dicts(con, f"SELECT * FROM store.lifecycle WHERE ip IN ({ph})", ips)}
    return {"name": name, "leads": leads, "ips": ips, "services": services, "appendix": appendix, "omitted": omitted,
            "conflicts": conflicts, "whole": whole, "cves": cves, "life": life, "today": today}


def attribution_line(lead):
    m, c = lead.get("attr_method"), lead.get("attr_confidence")
    if not m or (lead.get("org_name") or L.UNATTRIBUTED) == L.UNATTRIBUTED:
        return "unattributed — no registry attribution for this address", "none"
    if m == "shodan_org" or not lead.get("org_id"):
        return (f"Shodan org field '{esc(lead.get('org_name'))}' only — a network-operator label, not an ownership "
                f"record" + (f" (registry `{code(m, 40)}`: no organisation recorded)" if m != "shodan_org" else "")), \
            esc(c or "low", 10)
    return f"registry method `{code(m, 40)}`" + (f", org_id `{code(lead['org_id'], 60)}`" if lead.get("org_id") else ""), \
        esc(c or "low", 10)


def exposure_state(l, s, today=None):
    """('active'|'stale'|'gone'|'unknown', human label) for a lead's service. A
    host-level lead is judged by the age of its last EVENT (never "still observed"
    past 30 days)."""
    if l["transport"] == L.HOST_TRANSPORT:
        today = today or date.today()
        ev = L._parse_date(l.get("last_event") or l.get("last_seen"))
        if ev is None:
            return "unknown", "host-level evidence — event date unknown"
        age = (today - ev).days
        if age > L.HOST_EVENT_FRESH_DAYS:
            return "gone", f"no newer event — last event {ev} ({age} d ago)"
        return "active", f"host-level evidence — last event {ev} ({age} d ago)"
    if not s:
        return "unknown", "not in the store"
    st = s.get("status")
    if st == "active":
        return "active", f"currently active (last observed {s.get('date')})"
    if st == "stale":
        return "stale", f"stale — last observed {s.get('date')}, not seen for {s.get('days_since_seen')} d"
    return "gone", f"no longer observed — last observed {s.get('date')}"


def build_markdown(data):
    today, leads = data["today"], data["leads"]
    name = esc(data["name"])
    hist = [l for l in leads if l["status"] in OPEN_STATUSES
            and exposure_state(l, data["services"].get((l["ip"], l["port"], l["transport"])), today)[0] == "gone"]
    current = [l for l in leads if l not in hist]
    kinds = {kind_of(l) for l in current}
    compromise = bool(kinds & COMPROMISE_KINDS)
    if compromise or "kev_verified" in kinds:
        priority = "HIGH — recommend action within 24 hours"
    elif kinds & {"appliance", "ics", "shadowserver_exposure"} or any(l["confidence"] == "high" for l in current):
        priority = "MEDIUM — recommend action within 7 days"
    elif current:
        priority = "ROUTINE — review at next maintenance window"
    else:
        priority = "INFORMATIONAL — historical findings only"
    ref = f"LA-EXP-{today:%Y%m%d}-{slugify(data['name']).upper()[:12]}"
    sources = "Shodan" + (", Shadowserver" if kinds & {"shadowserver_compromise", "shadowserver_exposure"} else "")
    prev = [l for l in leads if l["status"] in PREVIOUSLY_NOTIFIED]
    prev_active = [l for l in prev if exposure_state(l, data["services"].get((l["ip"], l["port"], l["transport"])), today)[0] == "active"]
    closed = [l for l in leads if l["status"] not in OPEN_STATUSES]

    md = [f"# Security Notification — Internet-Exposed Services Attributed to {name}", "",
          "**Status:** DRAFT — not for release until the Reviewer sign-off block below is completed", "",
          f"**Prepared for:** {name} — IT / Information Security",
          f"**Prepared by:** {UNIT_PLACEHOLDER}",
          f"**Date:** {today}",
          f"**Reference:** {ref}",
          f"**Classification / handling:** {TLP_PLACEHOLDER} — FOR OFFICIAL USE ONLY; contains sensitive "
          "security findings about a named organisation",
          f"**Priority:** {priority}",
          f"**Method:** Passive analysis of public internet-scan and abuse-report data ({sources}); no scanning, "
          "probing or access of any system", "", "---", "", "## 1. Summary", "",
          f"During routine passive monitoring of Louisiana's internet-exposed systems we identified "
          f"**{len({l['ip'] for l in current})} host(s)** attributed to {name} carrying **{len(current)} current "
          "finding(s)** of the following kinds:", ""]
    md += [f"- {EVIDENCE_LABEL[k]}" for k in KIND_ORDER if k in kinds] or ["- (none currently observed)"]
    if prev:
        md += ["", f"{len(prev)} finding(s) were previously notified (marked below): "
                   + (f"{len(prev_active)} still observed" if prev_active else "none currently observed")
                   + (f", {len(prev) - len(prev_active)} listed with their last observation only." if len(prev) > len(prev_active) else ".")]
    if hist:
        md += ["", f"{len(hist)} further finding(s) are no longer observed and are listed for the record only."]
    if closed:
        md += ["", f"{len(closed)} finding(s) in a closed status are included because --include-closed was given."]
    if data["conflicts"]:
        md += ["", f"**Attribution conflict** on {len(data['conflicts'])} address(es) "
                   f"({', '.join(ipc(i) for i in sorted(data['conflicts']))}): our records disagree on the owner; "
                   "confirm before relying on those findings."]
    md += ["", "**This is a passive, external observation — a lead to verify, not confirmation of a breach or of "
           "a vulnerability.** We have not accessed, scanned, or interacted with your systems. The purpose of "
           "this notice is to put the information in your hands so you can investigate.", "", "---", "",
           "## 2. What we observed", "",
           "| # | IP | Port | Service / product | Evidence type | Confidence | Scan age | Exposure state | Attribution | Status |",
           "|---|---|---|---|---|---|---|---|---|---|"]

    def table_row(i, l):
        s = data["services"].get((l["ip"], l["port"], l["transport"])) or {}
        host_level = l["transport"] == L.HOST_TRANSPORT
        svc = "host-level" if host_level else (esc(L.service_desc(s)) if s else "not currently observed")
        age = days_ago(s.get("banner_ts") or s.get("date"), today) if s else days_ago(l.get("last_seen"), today)
        src = str(s.get("banner_ts") or s.get("date"))[:10] if s else str(l.get("last_seen"))[:10]
        age_s = f"{age} d ({esc(src, 10)})" if age is not None else "n/a"
        _, conf = attribution_line(l)
        port = "—" if host_level else f"{num(l['port'])}/{tp(l['transport'])}"
        stat = status_word(l["status"]) + (f" (previously notified on {dt(l.get('notified_on'))[:10]})"
                                           if l["status"] in PREVIOUSLY_NOTIFIED and l.get("notified_on") else "")
        state = exposure_state(l, s, today)[1]
        flag = " ⚠ attribution conflict" if l["ip"] in data["conflicts"] else ""
        return (f"| {i} | `{ipc(l['ip'])}` | {port} | {svc} | {kind_of(l)} | {esc(l['confidence'], 10)} | {age_s} | "
                f"{esc(state, 80)} | {conf}{flag} | {stat} |")

    for i, l in enumerate(current, 1):
        md.append(table_row(i, l))
    newest = max((str(s.get("date")) for s in data["services"].values()), default="n/a")
    md += ["", "Scan age = days since the scanner's own banner timestamp (or, if absent, our collection date / "
           f"the report date). Our newest collection day is {esc(newest, 10)}. Exposure state comes from "
           "exposure_status: active = seen in the last 14 days, stale = 15–45 days, gone = longer.", ""]
    if hist:
        md += ["### No longer observed — historical", "",
               "These findings were raised but the service has not been observed for more than 45 days (host-level "
               "evidence: no event for more than 30 days); they are listed so you can confirm the change was deliberate.", "",
               "| # | IP | Port | Service / product | Evidence type | Confidence | Scan age | Exposure state | Attribution | Status |",
               "|---|---|---|---|---|---|---|---|---|---|"]
        md += [table_row(f"H{i}", l) for i, l in enumerate(hist, 1)]
        md.append("")
    md += ["### Finding detail", ""]
    for i, l in enumerate(current + hist, 1):
        s = data["services"].get((l["ip"], l["port"], l["transport"])) or {}
        lf = data["life"].get((l["ip"], l["port"], l["transport"]))
        basis, conf = attribution_line(l)
        host_level = l["transport"] == L.HOST_TRANSPORT
        md += [f"#### Finding {i}: {ipc(l['ip'])}" + ("" if host_level else f":{num(l['port'])}/{tp(l['transport'])}")
               + f" — {EVIDENCE_LABEL[kind_of(l)]}", "",
               f"- **Evidence type / confidence:** {kind_of(l)} / {esc(l['confidence'], 10)}"
               + (f" (severity {esc(l['severity'], 10)})" if l.get("severity") else ""),
               f"- **Exact evidence:** {esc(l['evidence'], 400)}",
               f"- **Exposure state:** {esc(exposure_state(l, s, today)[1], 100)}"]
        if l["status"] in PREVIOUSLY_NOTIFIED:
            md.append(f"- **Previously notified:** on {dt(l.get('notified_on'))[:10] if l.get('notified_on') else 'unknown date'}"
                      + (f" via {esc(l.get('notified_via'), 40)}" if l.get("notified_via") else "")
                      + (" — still observed" if exposure_state(l, s, today)[0] == "active" else
                         f" — last observed {dt(s.get('date'))[:10] if s else dt(l.get('last_event') or l.get('last_seen'))[:10]}"))
        elif l["status"] not in OPEN_STATUSES:
            md.append(f"- **Status:** {status_word(l['status'])} (closed; included on request)")
        if l["ip"] in data["conflicts"]:
            md.append("- **Attribution conflict:** our lead records disagree on this address's owner — verify before acting")
        if s:
            md.append(f"- **Service as observed:** {esc(L.service_desc(s))}"
                      + (f"; module `{code(s.get('service'), 40)}`" if s.get("service") else "")
                      + (f"; HTTP title \"{esc(s['http_title'], 80)}\"" if s.get("http_title") else "")
                      + (f"; cpe `{code(s['cpe23'], 120)}`" if s.get("cpe23") else ""))
            md.append(f"- **Observed:** scanner banner {dt(s.get('banner_ts'))}; our collection date {dt(s.get('date'))[:10]}; "
                      f"freshness `{esc(s.get('status'), 10)}` ({num(s.get('days_since_seen'))} d since seen)")
            if s.get("cert_cn") or s.get("cert_org"):
                md.append(f"- **TLS certificate (for reference, not attribution):** CN `{code(s.get('cert_cn'))}` "
                          f"O `{code(s.get('cert_org'))}` issuer `{code(s.get('cert_issuer'))}`"
                          + (f"; SANs `{code(s['cert_sans'], 150)}`" if s.get("cert_sans") else ""))
            if s.get("hostnames"):
                md.append(f"- **Reverse DNS / hostnames:** `{code(s['hostnames'], 150)}`")
            if s.get("org"):
                md.append(f"- **Network operator (Shodan org, reference only):** {esc(s['org'])}")
        if lf:
            md.append(f"- **Dwell:** first seen in our data {dt(lf['first_seen'])[:10]}, last {dt(lf['last_seen'])[:10]} "
                      f"({num(lf['days_observed'])} collection day(s) over {num(lf['span_days'])} d)")
        for c in sorted(data["cves"].get((l["ip"], l["port"], l["transport"]), []),
                        key=lambda c: (not c["verified"], -(c["epss"] or 0))):
            if l["evidence_type"] in L.CVE_TYPES and c["cve"] != l.get("evidence_key"):
                continue
            md.append(f"- **{esc(c['cve'], 20)}** — CISA KEV; {'VERIFIED by scanner' if c['verified'] else 'version-inferred'}; "
                      f"CVSS {esc(c['cvss'], 6)}; EPSS {L._fmt_epss(c['epss'])}")
        md += [f"- **Attribution basis:** {basis} — confidence **{conf}**",
               f"- **Lead id:** `{lid(l['lead_id'])}` (status {status_word(l['status'])}, first raised "
               f"{dt(l['first_seen'])[:10]}, last scan {dt(l.get('last_scan_ts') or l.get('last_seen'))})", ""]

    md += ["---", "", "## 3. What this is not", "",
           "- **Not a scan of your systems.** Every observation above comes from a third-party internet-scan index "
           "(Shodan) and, where stated, Shadowserver's reports. We performed no active scanning, probing or access.",
           "- **Not a confirmed vulnerability.** CVE associations marked *inferred* come from advertised banner "
           "versions; they may be inaccurate or already patched. Exposure of a service is not evidence that it is "
           "vulnerable.",
           "- **Not a confirmed compromise.** " + ("This packet contains a compromise indicator; it is a credible "
           "lead that requires your verification — scanner threat flags and sinkhole hits can be stale, a shared "
           "address, or a false positive." if compromise else "No compromise indicator is included in this packet."),
           "- **Not necessarily current.** Findings reflect the scan ages and exposure states shown; a service may "
           "have changed since.",
           "- **Attribution is evidence-graded, not asserted.** The basis and confidence for tying each address to "
           f"{name} are stated per finding; if an address is not yours, please tell us so we can correct our records.",
           "", "---", "", "## 4. Recommended actions (in priority order)", ""]
    n = 1
    for k in KIND_ORDER:
        if k in kinds:
            for a in ACTIONS.get(k, []):
                md.append(f"{n}. {a}")
                n += 1
    md += [f"{n}. Cross-check the listed addresses against your asset inventory; unknown addresses are often "
           "forgotten or vendor-managed systems.",
           f"{n + 1}. No action is requested of any third party against these hosts; verification should be "
           "performed by the asset owner.", "",
           "**If any compromise evidence is found:** engage your incident-response process, preserve evidence, and "
           "contact us if we can assist.", "", "---", "", "## 5. How to verify", ""]
    md += [f"- **{EVIDENCE_LABEL[k]}:** {VERIFY.get(k, '')}" for k in KIND_ORDER if k in kinds]
    dates = [str(s["date"]) for s in data["services"].values()]
    md += ["", "We are glad to share the raw observation records for any finding on request.", "", "---", "",
           "## 6. Contact and handling", "",
           f"- **Contact:** {UNIT_PLACEHOLDER}",
           f"- **Handling:** {TLP_PLACEHOLDER}. Recipients may share this document only within their organisation "
           "and with those who need it to act on the information. Provided as a good-faith defensive courtesy; it "
           "confers no warranty and imposes no obligation.",
           "- **Source data:** passive scan data collected " + (f"{esc(min(dates), 10)} to {esc(max(dates), 10)}" if dates else "n/a")
           + f"; leads table as of {today}.", "", "---", "", "## Reviewer sign-off", "",
           "This packet is a DRAFT until every row below is completed.", "",
           "| Role | Name | Date | Signature |", "|---|---|---|---|",
           "| Preparing analyst | | | |",
           f"| Second reviewer ({'**REQUIRED** — this packet makes a compromise claim' if compromise else 'recommended'}) | | | |",
           "| Release approval | | | |", "",
           "Checklist before release: attribution confirmed for every address; TLP marking set; contact block "
           "filled; evidence dates re-checked against the store; "
           + ("compromise claim independently reviewed." if compromise else "no compromise claim is made."), "",
           "---", "", "## Appendix A — Services on these hosts", "",
           "Lead services are always listed. Other services on an address are listed only where the address has "
           f"whole-address ownership recorded for {name} in the current registry (registry network / OTS CIDR, high "
           "confidence, no conflict).", ""]
    if data["omitted"]:
        md.append(f"Other services on {len(data['omitted'])} address(es) omitted: shared/unresolved ownership "
                  f"({', '.join(ipc(i) for i in data['omitted'])}).")
        md.append("")
    md += ["| IP | Port | Product / service | Exposure state | Last seen | Title / cert |", "|---|---|---|---|---|---|"]
    for key in sorted(data["appendix"], key=lambda k: (k[0], k[1] or 0)):
        s = data["appendix"][key]
        md.append(f"| `{ipc(s['ip'])}` | {num(s['port'])}/{tp(s['transport'])} | {esc(L.service_desc(s))} | "
                  f"{esc(s.get('status'), 10)} | {dt(s['date'])[:10]} | {esc(s.get('http_title') or s.get('cert_cn') or '', 60)} |")
    if not data["appendix"]:
        md.append("| — | — | no service listed | — | — | — |")
    return "\n".join(md) + "\n"


# --- optional PDF ------------------------------------------------------------

def _inline(text):
    t = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"`([^`]*)`", r"<font face='Courier' size='7.5'>\1</font>", t)
    return re.sub(r"\\([\\`*_\[\]|<>#~])", r"\1", t)


def write_pdf(md, out_path, title):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    navy = colors.HexColor("#1f3a5f")
    st = {"title": ParagraphStyle("t", parent=ss["Title"], fontSize=15, leading=18, textColor=navy),
          "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontSize=12, textColor=navy, spaceBefore=10),
          "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontSize=10.5, textColor=navy, spaceBefore=6),
          "h3": ParagraphStyle("h3", parent=ss["Heading3"], fontSize=9.5, spaceBefore=4),
          "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=8.8, leading=12, spaceAfter=3),
          "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=7.2, leading=9)}
    story, table = [], []

    def flush_table():
        nonlocal table
        if not table:
            return
        rows = [[Paragraph(_inline(c.strip()), st["cell"]) for c in r] for r in table]
        ncol = max(len(r) for r in rows)
        t = Table(rows, colWidths=[7.0 * inch / ncol] * ncol, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        story.append(t)
        table = []

    for line in md.splitlines():
        if line.startswith("|"):
            cells = re.split(r"(?<!\\)\|", line.strip().strip("|"))
            if all(re.fullmatch(r"\s*:?-+:?\s*", c) for c in cells):
                continue
            table.append(cells)
            continue
        flush_table()
        if not line.strip():
            story.append(Spacer(1, 4))
        elif line.startswith("# "):
            story.append(Paragraph(_inline(line[2:]), st["title"]))
        elif line.startswith("## "):
            story.append(Paragraph(_inline(line[3:]), st["h1"]))
        elif line.startswith("### "):
            story.append(Paragraph(_inline(line[4:]), st["h2"]))
        elif line.startswith("#### "):
            story.append(Paragraph(_inline(line[5:]), st["h3"]))
        elif line.strip() == "---":
            story.append(Spacer(1, 6))
        elif line.startswith("- "):
            story.append(Paragraph("• " + _inline(line[2:]), st["body"]))
        else:
            story.append(Paragraph(_inline(line), st["body"]))
    flush_table()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawCentredString(letter[0] / 2, 0.35 * inch,
                                 f"DRAFT — {TLP_PLACEHOLDER} — FOR OFFICIAL USE ONLY — page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(out_path, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch, title=title)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Notification packet for one organisation.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--org", help="org_name or org_id (exact, case-insensitive; else whole-word, must be unique)")
    g.add_argument("--ip")
    ap.add_argument("--db", default=L.DB_PATH)
    ap.add_argument("--leads-dir", default=L.LEADS_DIR)
    ap.add_argument("--registry-dir", default=L.REGISTRY_DIR, help="store/registry (appendix authorization)")
    ap.add_argument("--out-dir", default=PACKET_DIR)
    ap.add_argument("--date", help="YYYY-MM-DD (default today)")
    ap.add_argument("--include-closed", action="store_true")
    ap.add_argument("--pdf", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the markdown, write nothing")
    args = ap.parse_args(argv)
    today = L._parse_date(args.date) if args.date else date.today()
    if args.date and today is None:
        ap.error("--date must be YYYY-MM-DD")
    ctx = L.open_ctx(args.db, args.leads_dir, write=False)
    try:
        data = gather(ctx, today, org=args.org, ip=args.ip, include_closed=args.include_closed,
                      registry_dir=args.registry_dir)
    finally:
        ctx.close()
    md = build_markdown(data)
    if args.dry_run:
        print(md)
        return 0
    os.makedirs(args.out_dir, exist_ok=True)
    base = os.path.join(args.out_dir, f"{slugify(data['name'])}_{today}")
    with open(base + ".md", "w") as fh:
        fh.write(md)
    L.log(f"wrote {base}.md ({len(data['leads'])} finding(s), {len(data['ips'])} host(s)) — DRAFT until signed off")
    if args.pdf:
        try:
            write_pdf(md, base + ".pdf", f"Notification — {data['name']}")
            L.log(f"wrote {base}.pdf")
        except Exception as exc:
            L.log(f"PDF not written ({exc}); markdown is complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
