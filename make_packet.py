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

Rules: by default only leads in status new/queued (and notified/acknowledged,
marked "previously notified on <date>") are included; the selected leads must all
attribute to ONE organisation (otherwise the packet is refused and the orgs
listed); residential/honeypot-tier leads are refused independently of leads.py;
the appendix lists only CURRENTLY ACTIVE services on the lead hosts whose
attribution names the same org. Every banner-derived string (product, title,
hostnames, org, evidence …) is escaped before it enters the markdown. The packet
is marked DRAFT until the reviewer block is completed; a compromise claim requires
a second reviewer. Attribution is stated as the registry recorded it; a host with
no registry attribution is "unattributed" — the Shodan org label is shown for
reference only and never promoted to an attribution.

Output: reports/packets/<org-slug>_<date>.md (+ .pdf).
"""
import argparse
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


def esc(s, limit=200):
    """Escape untrusted banner-derived text for markdown: control chars and
    newlines collapse to a space; markdown-active characters are backslash-escaped."""
    if s is None:
        return ""
    t = _CTRL_RE.sub(" ", str(s))
    t = _ESC_RE.sub(r"\\\1", t)
    return t[:limit] + ("…" if len(t) > limit else "")


def code(s, limit=200):
    """Escape untrusted text for a backtick code span (also inside a table cell):
    backticks would end the span, pipes would split the cell, newlines the row."""
    if s is None:
        return ""
    t = _CTRL_RE.sub(" ", str(s)).replace("`", "'").replace("|", "\\|")
    return t[:limit] + ("…" if len(t) > limit else "")


def slugify(s):
    s = re.sub(r"[^A-Za-z0-9]+", "_", s or "org").strip("_")
    return (s or "org")[:60]


def kind_of(lead):
    if lead["evidence_type"] == "shadowserver":
        return "shadowserver_compromise" if str(lead.get("evidence_key") or "").startswith("compromise") \
            else "shadowserver_exposure"
    return lead["evidence_type"]


def org_key(lead):
    return (lead.get("org_id") or "").strip().lower() or f"name:{(lead.get('org_name') or '').strip().lower()}"


def days_ago(d, today):
    d = L._parse_date(d)
    return None if d is None else (today - d).days


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
    dropped = [r for r in rows if (r.get("tier") or "") in L.NEVER_LEAD_TIERS]
    rows = [r for r in rows if r not in dropped]
    if dropped:
        L.log(f"refused {len(dropped)} residential/honeypot-tier lead(s): not a notification target")
    if not rows:
        raise SystemExit(f"No open leads for {org or ip!r} (statuses {', '.join(statuses or ['any'])}). "
                         f"Run `leads.py refresh` or `leads.py list --org`.")
    orgs = {}
    for r in rows:
        orgs.setdefault(org_key(r), r.get("org_name") or L.UNATTRIBUTED)
    if len(orgs) > 1:
        raise SystemExit("ERROR: the selected leads attribute to more than one organisation — one packet per "
                         "org:\n  " + "\n  ".join(sorted(set(orgs.values()))))
    return rows


def gather(ctx, today, org=None, ip=None, include_closed=False):
    con = ctx.con
    leads = select_leads(ctx, org, ip, include_closed)
    name = leads[0].get("org_name") or L.UNATTRIBUTED
    okey = org_key(leads[0])
    ips = sorted({l["ip"] for l in leads})
    ph = ", ".join("?" * len(ips))
    # attribution of every lead host (all leads on an ip share it)
    ip_org = {r["ip"]: org_key(r) for r in L.fetch_dicts(con, f"SELECT ip, org_id, org_name FROM leads WHERE ip IN ({ph})", ips)}
    wanted = ["ip", "port", "transport", "date", "status", "days_since_seen", "org", "product", "version",
              "service", "cpe23", "http_title", "hostnames", "banner_ts", "cert_cn", "cert_org", "cert_issuer",
              "cert_sans", "tier", "tier_reason"]
    services = {}
    have = set(L.columns_of(con, "exposure_status", "store"))
    cols = ", ".join(c if c in have else f"NULL AS {c}" for c in wanted)
    for r in L.fetch_dicts(con, f"SELECT {cols} FROM store.exposure_status WHERE ip IN ({ph})", ips):
        services[(r["ip"], r["port"], r["transport"])] = r
    active_same_org = {k: r for k, r in services.items() if r["status"] == "active" and ip_org.get(r["ip"]) == okey}
    cves = {}
    for r in L.fetch_dicts(con, f"""
            SELECT lo.ip, lo.port, lo.transport, v.cve, v.cvss, v.epss, v.verified
            FROM store.latest_observed lo JOIN store.vulns v ON v.observation_id = lo.observation_id AND v.date = lo.date
            WHERE lo.ip IN ({ph}) AND v.in_kev""", ips):
        cves.setdefault((r["ip"], r["port"], r["transport"]), []).append(r)
    life = {(r["ip"], r["port"], r["transport"]): r for r in
            L.fetch_dicts(con, f"SELECT * FROM store.lifecycle WHERE ip IN ({ph})", ips)}
    return {"name": name, "leads": leads, "ips": ips, "services": services, "active_same_org": active_same_org,
            "cves": cves, "life": life, "today": today}


def attribution_line(lead):
    m, c = lead.get("attr_method"), lead.get("attr_confidence")
    if not m or (lead.get("org_name") or L.UNATTRIBUTED) == L.UNATTRIBUTED:
        return "unattributed — no registry attribution for this address", "none"
    if m == "shodan_org":
        return (f"Shodan org field '{esc(lead.get('org_name'))}' only — a network-operator label, not an "
                f"ownership record"), c or "low"
    return f"registry method `{code(m)}`" + (f", org_id `{code(lead['org_id'])}`" if lead.get("org_id") else ""), c or "low"


def build_markdown(data):
    today, name, leads = data["today"], esc(data["name"]), data["leads"]
    kinds = {kind_of(l) for l in leads}
    compromise = bool(kinds & COMPROMISE_KINDS)
    if compromise or "kev_verified" in kinds:
        priority = "HIGH — recommend action within 24 hours"
    elif kinds & {"appliance", "ics", "shadowserver_exposure"} or any(l["confidence"] == "high" for l in leads):
        priority = "MEDIUM — recommend action within 7 days"
    else:
        priority = "ROUTINE — review at next maintenance window"
    ref = f"LA-EXP-{today:%Y%m%d}-{slugify(data['name']).upper()[:12]}"
    sources = "Shodan" + (", Shadowserver" if kinds & {"shadowserver_compromise", "shadowserver_exposure"} else "")
    prev = [l for l in leads if l["status"] in PREVIOUSLY_NOTIFIED]
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
          f"**{len(data['ips'])} host(s)** attributed to {name} carrying **{len(leads)} finding(s)** of the "
          "following kinds:", ""]
    md += [f"- {EVIDENCE_LABEL[k]}" for k in KIND_ORDER if k in kinds]
    if prev:
        md += ["", f"{len(prev)} of these finding(s) were previously notified (marked below); this packet "
                   "re-states them because they are still observed."]
    if closed:
        md += ["", f"{len(closed)} finding(s) in a closed status are included because --include-closed was given."]
    md += ["", "**This is a passive, external observation — a lead to verify, not confirmation of a breach or of "
           "a vulnerability.** We have not accessed, scanned, or interacted with your systems. The purpose of "
           "this notice is to put the information in your hands so you can investigate.", "", "---", "",
           "## 2. What we observed", "",
           "| # | IP | Port | Service / product | Evidence type | Confidence | Scan age | Attribution | Status |",
           "|---|---|---|---|---|---|---|---|---|"]
    for i, l in enumerate(leads, 1):
        s = data["services"].get((l["ip"], l["port"], l["transport"])) or {}
        host_level = l["transport"] == L.HOST_TRANSPORT
        svc = "host-level" if host_level else (esc(L.service_desc(s)) if s else "not currently observed")
        age = days_ago(s.get("banner_ts") or s.get("date"), today) if s else days_ago(l.get("last_seen"), today)
        src = str(s.get("banner_ts") or s.get("date"))[:10] if s else str(l.get("last_seen"))
        age_s = f"{age} d ({src})" if age is not None else "n/a"
        _, conf = attribution_line(l)
        port = "—" if host_level else f"{l['port']}/{l['transport']}"
        stat = l["status"] + (f" (previously notified on {l.get('notified_on')})"
                                   if l["status"] in PREVIOUSLY_NOTIFIED and l.get("notified_on") else "")
        md.append(f"| {i} | `{code(l['ip'])}` | {port} | {svc} | {kind_of(l)} | {l['confidence']} | "
                  f"{age_s} | {conf} | {stat} |")
    newest = max((str(s.get("date")) for s in data["services"].values()), default="n/a")
    md += ["", "Scan age = days since the scanner's own banner timestamp (or, if absent, our collection date / "
           f"the report date). Our newest collection day is {newest}.", "", "### Finding detail", ""]
    for i, l in enumerate(leads, 1):
        s = data["services"].get((l["ip"], l["port"], l["transport"])) or {}
        lf = data["life"].get((l["ip"], l["port"], l["transport"]))
        basis, conf = attribution_line(l)
        host_level = l["transport"] == L.HOST_TRANSPORT
        md += [f"#### Finding {i}: {code(l['ip'])}" + ("" if host_level else f":{l['port']}/{l['transport']}")
               + f" — {EVIDENCE_LABEL.get(kind_of(l), kind_of(l))}", "",
               f"- **Evidence type / confidence:** {kind_of(l)} / {l['confidence']}"
               + (f" (severity {esc(l['severity'])})" if l.get("severity") else ""),
               f"- **Exact evidence:** {esc(l['evidence'], 400)}"]
        if l["status"] in PREVIOUSLY_NOTIFIED:
            md.append(f"- **Previously notified:** on {l.get('notified_on') or 'unknown date'}"
                      + (f" via {esc(l.get('notified_via'))}" if l.get("notified_via") else "") + " — still observed")
        elif l["status"] not in OPEN_STATUSES:
            md.append(f"- **Status:** {l['status']} (closed; included on request)")
        if s:
            md.append(f"- **Service as observed:** {esc(L.service_desc(s))}"
                      + (f"; module `{code(s.get('service'))}`" if s.get("service") else "")
                      + (f"; HTTP title \"{esc(s['http_title'], 80)}\"" if s.get("http_title") else "")
                      + (f"; cpe `{code(s['cpe23'], 120)}`" if s.get("cpe23") else ""))
            md.append(f"- **Observed:** scanner banner {esc(str(s.get('banner_ts'))[:19])}; our collection date "
                      f"{s.get('date')}; freshness `{s.get('status')}` ({s.get('days_since_seen')} d since seen)")
            if s.get("cert_cn") or s.get("cert_org"):
                md.append(f"- **TLS certificate (for reference, not attribution):** CN `{code(s.get('cert_cn'))}` "
                          f"O `{code(s.get('cert_org'))}` issuer `{code(s.get('cert_issuer'))}`"
                          + (f"; SANs `{code(s['cert_sans'], 150)}`" if s.get("cert_sans") else ""))
            if s.get("hostnames"):
                md.append(f"- **Reverse DNS / hostnames:** `{code(s['hostnames'], 150)}`")
            if s.get("org"):
                md.append(f"- **Network operator (Shodan org, reference only):** {esc(s['org'])}")
        if lf:
            md.append(f"- **Dwell:** first seen in our data {lf['first_seen']}, last {lf['last_seen']} "
                      f"({lf['days_observed']} collection day(s) over {lf['span_days']} d)")
        for c in sorted(data["cves"].get((l["ip"], l["port"], l["transport"]), []),
                        key=lambda c: (not c["verified"], -(c["epss"] or 0))):
            if l["evidence_type"] in L.CVE_TYPES and c["cve"] != l.get("evidence_key"):
                continue
            md.append(f"- **{esc(c['cve'])}** — CISA KEV; {'VERIFIED by scanner' if c['verified'] else 'version-inferred'}; "
                      f"CVSS {c['cvss'] or 'n/a'}; EPSS {L._fmt_epss(c['epss'])}")
        md += [f"- **Attribution basis:** {basis} — confidence **{esc(conf)}**",
               f"- **Lead id:** `{l['lead_id']}` (status {l['status']}, first raised {l['first_seen']}, "
               f"last observed {l.get('last_seen')})", ""]

    md += ["---", "", "## 3. What this is not", "",
           "- **Not a scan of your systems.** Every observation above comes from a third-party internet-scan index "
           "(Shodan) and, where stated, Shadowserver's reports. We performed no active scanning, probing or access.",
           "- **Not a confirmed vulnerability.** CVE associations marked *inferred* come from advertised banner "
           "versions; they may be inaccurate or already patched. Exposure of a service is not evidence that it is "
           "vulnerable.",
           "- **Not a confirmed compromise.** " + ("This packet contains a compromise indicator; it is a credible "
           "lead that requires your verification — scanner threat flags and sinkhole hits can be stale, a shared "
           "address, or a false positive." if compromise else "No compromise indicator is included in this packet."),
           "- **Not necessarily current.** Findings reflect the scan ages shown; a service may have changed since.",
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
           "- **Source data:** passive scan data collected " + (f"{min(dates)} to {max(dates)}" if dates else "n/a")
           + f"; leads table as of {today}.", "", "---", "", "## Reviewer sign-off", "",
           "This packet is a DRAFT until every row below is completed.", "",
           "| Role | Name | Date | Signature |", "|---|---|---|---|",
           "| Preparing analyst | | | |",
           f"| Second reviewer ({'**REQUIRED** — this packet makes a compromise claim' if compromise else 'recommended'}) | | | |",
           "| Release approval | | | |", "",
           "Checklist before release: attribution confirmed for every address; TLP marking set; contact block "
           "filled; evidence dates re-checked against the store; "
           + ("compromise claim independently reviewed." if compromise else "no compromise claim is made."), "",
           "---", "", "## Appendix A — Currently active services on these hosts", "",
           f"Only services observed in the last 14 days on hosts whose attribution names {name}.", "",
           "| IP | Port | Product / service | Last seen | Title / cert |", "|---|---|---|---|---|"]
    for key in sorted(data["active_same_org"], key=lambda k: (k[0], k[1])):
        s = data["active_same_org"][key]
        md.append(f"| `{code(s['ip'])}` | {s['port']}/{s['transport']} | {esc(L.service_desc(s))} | "
                  f"{s['date']} | {esc(s.get('http_title') or s.get('cert_cn') or '', 60)} |")
    if not data["active_same_org"]:
        md.append("| — | — | no currently active service attributed to this organisation | — | — |")
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
    ap.add_argument("--leads-db", default=L.LEADS_DB)
    ap.add_argument("--out-dir", default=PACKET_DIR)
    ap.add_argument("--date", help="YYYY-MM-DD (default today)")
    ap.add_argument("--include-closed", action="store_true",
                    help="also include remediated / disputed / false_positive / suppressed leads")
    ap.add_argument("--pdf", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the markdown, write nothing")
    args = ap.parse_args(argv)
    today = L._parse_date(args.date) if args.date else date.today()
    if args.date and today is None:
        ap.error("--date must be YYYY-MM-DD")
    if not os.path.exists(args.leads_db):
        raise SystemExit("No leads yet — run `leads.py refresh` first.")
    ctx = L.open_ctx(args.db, args.leads_db, write=False)
    try:
        data = gather(ctx, today, org=args.org, ip=args.ip, include_closed=args.include_closed)
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
