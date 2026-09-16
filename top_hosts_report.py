#!/usr/bin/env python3
"""
top_hosts_report.py — the "most vulnerable currently exposed hosts" report,
per sector, as a self-contained PDF (plus a CSV for analysts).

Ranks every host in current_state (seen in the last 14 days) by vulnerability
evidence and lists the top N per tier. Honeypots are always excluded; the
residential tier is excluded by default (home connections are reported to ISPs
in aggregate, never listed by IP). Every host carries a clickable link to its
Shodan page. Passive data: every row is a LEAD TO VERIFY, not a confirmed
vulnerability.

Score per host (see SCORE_WEIGHTS):
  200 per KEV CVE Shodan verified on the host; 120 per KEV CVE with a public
  Metasploit/Nuclei exploit; 60 per other CISA KEV CVE; 50 if on a threat feed;
  40 per exposed ICS protocol; 30 for an exposed edge appliance; 25 per exposed
  database; 15 per exposed admin service; + max EPSS x 50 + max CVSS.

Usage:
    top_hosts_report.py                       # reports/top_hosts_<date>.pdf + .csv
    top_hosts_report.py --per-tier 25 --tiers critical_infrastructure,government,education,small_business,unclassified
    top_hosts_report.py --include-residential # only for internal use
    top_hosts_report.py --marking "TLP:AMBER"
"""
import argparse
import csv
import datetime as dt
import html
import json
import os
import sys

import duckdb

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "store", "exposure.duckdb")
OUT_DIR = os.path.join(SCRIPT_DIR, "reports")

TIER_TITLE = {"critical_infrastructure": "Critical infrastructure", "government": "Government",
              "education": "Education", "small_business": "Business",
              "unclassified": "Unattributed carrier space", "out_of_state_gov": "Out-of-state government",
              "residential": "Residential"}
DEFAULT_TIERS = ["critical_infrastructure", "government", "education", "small_business", "unclassified"]
SCORE_WEIGHTS = {"kev_verified": 200, "kev_exploit": 120, "kev": 60, "ioc": 50, "ics": 40,
                 "appliance": 30, "db_port": 25, "admin_port": 15, "epss": 50}
ADMIN_PORTS = "(23,3389,5900,21,445,512,513,514)"
DB_PORTS = "(3306,5432,27017,6379,9200,1433,11211,5984,9042)"
ICS_PORTS = "(502,20000,47808,102,44818,1911,2404,789,1962,9600,20547)"

SQL = f"""
WITH hosts AS (
  SELECT cs.ip,
         any_value(cs.tier) AS tier, any_value(cs.org) AS org, any_value(cs.city) AS city,
         any_value(cs.asn) AS asn, any_value(cs.attr_org_name) AS attr_org,
         any_value(cs.attr_method) AS attr_method, any_value(cs.attr_confidence) AS attr_conf,
         count(*) AS services,
         list(DISTINCT cs.port ORDER BY cs.port) AS ports,
         string_agg(DISTINCT coalesce(cs.product,''), ',') AS products,
         string_agg(DISTINCT coalesce(cs.hostnames,''), ',') AS hostnames,
         string_agg(DISTINCT coalesce(cs.cert_org,''), ',') AS cert_orgs,
         max(cs.date) AS last_seen,
         bool_or(coalesce(cs.tags,'') LIKE '%honeypot%') AS hp_tag,
         count(DISTINCT CASE WHEN cs.port IN {ICS_PORTS}
                              OR cs.service IN ('modbus','siemens_s7','bacnet','ethernetip','dnp3','iec-104')
                         THEN cs.port END) AS ics,
         count(DISTINCT CASE WHEN cs.port IN {ADMIN_PORTS} THEN cs.port END) AS admin_ports,
         count(DISTINCT CASE WHEN cs.port IN {DB_PORTS} THEN cs.port END) AS db_ports
  FROM current_state cs GROUP BY cs.ip
), v AS (
  SELECT cs.ip,
         count(DISTINCT v.cve) AS cves,
         count(DISTINCT CASE WHEN v.in_kev THEN v.cve END) AS kev,
         count(DISTINCT CASE WHEN v.in_kev AND v.verified THEN v.cve END) AS kev_verified,
         count(DISTINCT CASE WHEN v.in_kev AND v.has_exploit THEN v.cve END) AS kev_exploit,
         max(v.cvss) AS max_cvss, max(v.epss) AS max_epss,
         string_agg(DISTINCT CASE WHEN v.in_kev THEN v.cve END, ' ') AS kev_list
  FROM current_state cs JOIN vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
  GROUP BY cs.ip
), a AS (SELECT ip, string_agg(DISTINCT appliance, ', ') AS appliances FROM appliance_exposure GROUP BY ip),
   i AS (SELECT ip, string_agg(DISTINCT ioc_sources, ',') AS ioc FROM ioc_matches GROUP BY ip)
SELECT h.*, coalesce(v.cves,0) AS cves, coalesce(v.kev,0) AS kev, coalesce(v.kev_verified,0) AS kev_verified,
       coalesce(v.kev_exploit,0) AS kev_exploit, v.max_cvss, v.max_epss, v.kev_list, a.appliances, i.ioc,
       (coalesce(v.kev_verified,0)*{SCORE_WEIGHTS['kev_verified']} + coalesce(v.kev_exploit,0)*{SCORE_WEIGHTS['kev_exploit']}
        + coalesce(v.kev,0)*{SCORE_WEIGHTS['kev']} + h.ics*{SCORE_WEIGHTS['ics']}
        + (CASE WHEN a.appliances IS NOT NULL THEN {SCORE_WEIGHTS['appliance']} ELSE 0 END)
        + (CASE WHEN i.ioc IS NOT NULL THEN {SCORE_WEIGHTS['ioc']} ELSE 0 END)
        + h.admin_ports*{SCORE_WEIGHTS['admin_port']} + h.db_ports*{SCORE_WEIGHTS['db_port']}
        + coalesce(v.max_epss,0)*{SCORE_WEIGHTS['epss']} + coalesce(v.max_cvss,0)) AS score
FROM hosts h LEFT JOIN v ON v.ip = h.ip LEFT JOIN a ON a.ip = h.ip LEFT JOIN i ON i.ip = h.ip
WHERE h.tier <> 'honeypot' AND NOT h.hp_tag AND h.services <= 100
"""


def load(db_path):
    con = duckdb.connect(db_path, read_only=True)
    cols = [d[0] for d in con.execute(SQL + " LIMIT 0").description]
    rows = [dict(zip(cols, r)) for r in con.execute(SQL).fetchall()]
    meta = {"newest_day": str(con.execute("SELECT max(date) FROM observations").fetchone()[0]),
            "days": con.execute("SELECT count(DISTINCT date) FROM observations").fetchone()[0],
            "honeypots": con.execute("SELECT count(DISTINCT ip) FROM current_state "
                                     "WHERE tier='honeypot' OR coalesce(tags,'') LIKE '%honeypot%'").fetchone()[0]}
    con.close()
    return rows, meta


def evidence_words(r):
    ev = []
    if r["kev_verified"]:
        ev.append(f"{r['kev_verified']} KEV verified by Shodan")
    if r["kev_exploit"]:
        ev.append(f"{r['kev_exploit']} KEV with public exploit")
    other = r["kev"] - max(r["kev_verified"], r["kev_exploit"])
    if r["kev"] and not r["kev_verified"] and not r["kev_exploit"]:
        ev.append(f"{r['kev']} KEV (version-inferred)")
    elif other > 0:
        ev.append(f"{r['kev']} KEV total")
    if r["ics"]:
        ev.append(f"{r['ics']} ICS protocol{'s' if r['ics'] > 1 else ''} exposed")
    if r.get("appliances"):
        ev.append(r["appliances"])
    if r.get("ioc"):
        ev.append(f"threat feed: {r['ioc']}")
    if r["admin_ports"]:
        ev.append(f"{r['admin_ports']} admin service{'s' if r['admin_ports'] > 1 else ''}")
    if r["db_ports"]:
        ev.append(f"{r['db_ports']} database service{'s' if r['db_ports'] > 1 else ''}")
    return "; ".join(ev)


def owner_words(r):
    if r.get("attr_org") and r.get("attr_conf") in ("high", "medium"):
        return f"{r['attr_org']} ({r['attr_conf']}, {r['attr_method']})"
    return f"{r.get('org') or '?'} (operator label)"


def first_n(csv_text, n):
    return ", ".join(sorted({x for x in (csv_text or "").split(",") if x})[:n])


def write_csv(path, sections):
    cols = ["tier", "rank", "ip", "shodan_url", "owner", "attr_confidence", "attr_method", "shodan_org", "city",
            "asn", "score", "kev_verified", "kev_exploit", "kev", "cves", "max_cvss", "max_epss", "ics",
            "appliances", "ioc", "admin_ports", "db_ports", "services", "ports", "products", "hostnames",
            "cert_orgs", "kev_list", "last_seen"]
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for tier, rows in sections.items():
            for i, r in enumerate(rows, 1):
                w.writerow([tier, i, r["ip"], f"https://www.shodan.io/host/{r['ip']}", owner_words(r),
                            r.get("attr_conf"), r.get("attr_method"), r.get("org"), r.get("city"), r.get("asn"),
                            round(r["score"], 1), r["kev_verified"], r["kev_exploit"], r["kev"], r["cves"],
                            r.get("max_cvss"), r.get("max_epss"), r["ics"], r.get("appliances"), r.get("ioc"),
                            r["admin_ports"], r["db_ports"], r["services"],
                            " ".join(str(p) for p in (r["ports"] or [])), first_n(r.get("products"), 6),
                            first_n(r.get("hostnames"), 6), first_n(r.get("cert_orgs"), 3), r.get("kev_list"),
                            r["last_seen"]])


def write_pdf(path, sections, totals, meta, marking, per_tier, residential_excluded, n_scored):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import landscape, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.2, leading=10.2)
    small = ParagraphStyle("small", parent=body, fontSize=7.2, leading=8.8, textColor=colors.HexColor("#4A5461"))
    cell = ParagraphStyle("cell", parent=body, fontSize=7.6, leading=9.4)
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24,
                        alignment=TA_LEFT, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=17,
                        spaceBefore=4, spaceAfter=4)
    ink = colors.HexColor("#1B2430")
    rule = colors.HexColor("#D3D6CF")
    stripe = {"critical_infrastructure": colors.HexColor("#A8352F"), "government": colors.HexColor("#3F5A8C"),
              "education": colors.HexColor("#6E4C7E")}
    generated = dt.date.today().isoformat()

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(colors.HexColor("#A8352F"))
        canvas.drawCentredString(landscape(letter)[0] / 2, landscape(letter)[1] - 0.35 * inch, marking)
        canvas.drawCentredString(landscape(letter)[0] / 2, 0.3 * inch, marking)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#7A8390"))
        canvas.drawString(0.5 * inch, 0.3 * inch, f"Louisiana exposure census — top exposed hosts by sector — generated {generated}")
        canvas.drawRightString(landscape(letter)[0] - 0.5 * inch, 0.3 * inch, f"page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(path, pagesize=landscape(letter), leftMargin=0.5 * inch, rightMargin=0.5 * inch,
                            topMargin=0.55 * inch, bottomMargin=0.55 * inch,
                            title="Louisiana Top Exposed Hosts by Sector", author="Louisiana exposure census")
    story = []
    story.append(Paragraph("Louisiana Top Exposed Hosts by Sector", h1))
    story.append(Paragraph(
        f"Passive exposure census · store as of {meta['newest_day']} · {meta['days']} days of collection · "
        f"{n_scored:,} active hosts scored · generated {generated}", small))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"The {per_tier} currently observed hosts with the strongest vulnerability evidence in each sector, ranked by "
        "verified and exploitable known-exploited CVEs, exposed industrial protocols, edge appliances, threat-feed "
        "hits and exposed admin services. Every host links to its Shodan page. <b>Every row is a lead to verify by "
        "contacting the owner, not a confirmed vulnerability: nothing here was probed.</b> A CVE attached to a host "
        "is Shodan's inference from the software version in the banner unless marked verified.", body))
    story.append(Spacer(1, 6))
    tot = "  ·  ".join(f"<b>{TIER_TITLE.get(t, t)}</b> {totals.get(t, 0):,}" for t in sections)
    story.append(Paragraph(f"Active hosts by sector: {tot}. Excluded: {meta['honeypots']} honeypots"
                           + (f", {residential_excluded:,} residential subscriber hosts (reported to ISPs in aggregate, never by IP)"
                              if residential_excluded else "") + ".", body))
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>How the score works.</b> "
                           f"{SCORE_WEIGHTS['kev_verified']} per KEV CVE Shodan verified on the host; "
                           f"{SCORE_WEIGHTS['kev_exploit']} per KEV CVE with a public Metasploit or Nuclei exploit; "
                           f"{SCORE_WEIGHTS['kev']} per other CISA KEV CVE; {SCORE_WEIGHTS['ioc']} if the IP is on a threat feed "
                           f"(Spamhaus DROP, CINS, abuse.ch, URLhaus); {SCORE_WEIGHTS['ics']} per exposed ICS protocol; "
                           f"{SCORE_WEIGHTS['appliance']} for an exposed edge appliance; {SCORE_WEIGHTS['db_port']} per exposed "
                           f"database; {SCORE_WEIGHTS['admin_port']} per exposed admin service (RDP, VNC, Telnet, SMB, FTP); "
                           f"plus max EPSS × {SCORE_WEIGHTS['epss']} and max CVSS.", body))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Reading a row.</b> The owner column shows the registry attribution with its confidence and "
                           "method; <i>operator label</i> means only the carrier's org field is known and the customer "
                           "behind the IP is unattributed — attribution work comes before any notification. CVSS is the "
                           "highest on the host; EPSS is the probability of exploitation within 30 days. Only hosts seen "
                           "in the last 14 days count as current.", body))
    story.append(PageBreak())

    widths = [0.3 * inch, 1.35 * inch, 1.9 * inch, 0.5 * inch, 2.6 * inch, 0.6 * inch, 1.9 * inch, 0.75 * inch]
    for tier, rows in sections.items():
        if not rows:
            continue
        hi = sum(1 for r in rows if r["kev_verified"] or r["kev_exploit"])
        ics = sum(1 for r in rows if r["ics"])
        ioc = sum(1 for r in rows if r.get("ioc"))
        head = [Paragraph(TIER_TITLE.get(tier, tier), h2),
                Paragraph(f"{len(rows)} shown of {totals.get(tier, 0):,} active hosts · {hi} with a verified or "
                          f"exploitable KEV CVE · {ics} with ICS exposed · {ioc} on a threat feed", small),
                Spacer(1, 4)]
        data = [[Paragraph(f"<b>{h}</b>", small) for h in
                 ("#", "Host", "Owner", "Score", "Evidence", "CVSS / EPSS", "Services", "Last seen")]]
        for i, r in enumerate(rows, 1):
            url = f"https://www.shodan.io/host/{r['ip']}"
            host = (f'<link href="{url}" color="#1F5C46"><b>{html.escape(r["ip"])}</b></link><br/>'
                    f'<font size="6.6" color="#4A5461">{html.escape(r.get("city") or "")}'
                    f'{" · " if r.get("city") and r.get("asn") else ""}{html.escape(r.get("asn") or "")}</font><br/>'
                    f'<link href="{url}" color="#1F5C46"><font size="6.6">Shodan page</font></link>')
            names = first_n(r.get("hostnames"), 2)
            certs = first_n(r.get("cert_orgs"), 1)
            owner = html.escape(owner_words(r))
            if certs:
                owner += f'<br/><font size="6.6" color="#4A5461">cert: {html.escape(certs)}</font>'
            if names:
                owner += f'<br/><font size="6.6" color="#4A5461">{html.escape(names)}</font>'
            kevs = (r.get("kev_list") or "").split()
            ev = html.escape(evidence_words(r))
            if kevs:
                ev += f'<br/><font name="Courier" size="6.4">{" ".join(kevs[:5])}{" …" if len(kevs) > 5 else ""}</font>'
            cv = f"{r['max_cvss']:.1f}" if r.get("max_cvss") else "—"
            ep = f"{r['max_epss']:.2f}" if r.get("max_epss") else "—"
            ports = r["ports"] or []
            svc = (f"{r['services']} svc<br/><font size=\"6.6\" color=\"#4A5461\">"
                   f"{html.escape(', '.join(str(p) for p in ports[:12]))}{' …' if len(ports) > 12 else ''}</font>")
            prods = first_n(r.get("products"), 3)
            if prods:
                svc += f'<br/><font size="6.6" color="#4A5461">{html.escape(prods)}</font>'
            data.append([Paragraph(str(i), cell), Paragraph(host, cell), Paragraph(owner, cell),
                         Paragraph(f"<b>{r['score']:.0f}</b>", cell), Paragraph(ev, cell),
                         Paragraph(f"{cv}<br/><font size=\"6.6\" color=\"#4A5461\">EPSS {ep}</font>", cell),
                         Paragraph(svc, cell), Paragraph(str(r["last_seen"]), cell)])
        t = Table(data, colWidths=widths, repeatRows=1)
        style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, 0), 0.8, ink),
                 ("LINEBELOW", (0, 1), (-1, -1), 0.3, rule), ("LEFTPADDING", (0, 0), (-1, -1), 4),
                 ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3),
                 ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        if tier in stripe:
            style.append(("LINEBEFORE", (0, 1), (0, -1), 2.5, stripe[tier]))
        t.setStyle(TableStyle(style))
        story.append(KeepTogether(head + [t] if len(rows) <= 8 else head))
        if len(rows) > 8:
            story.append(t)
        story.append(PageBreak())
    story.append(Paragraph("Source: the exposure store (current_state joined to vulns on date and observation_id, "
                           "appliance_exposure and ioc_matches views); owner from the Phase 2 registry generation. "
                           "KEV = CISA Known Exploited Vulnerabilities. Passive Shodan data only; findings are leads "
                           "to verify. Generated by top_hosts_report.py.", small))
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def main():
    ap = argparse.ArgumentParser(description="Top exposed hosts per sector: PDF + CSV.")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--out", default=OUT_DIR)
    ap.add_argument("--per-tier", type=int, default=25)
    ap.add_argument("--tiers", default=",".join(DEFAULT_TIERS))
    ap.add_argument("--include-residential", action="store_true", help="internal use only")
    ap.add_argument("--marking", default="FOUO — DRAFT — LEADS TO VERIFY — NOT FOR ONWARD DISTRIBUTION")
    args = ap.parse_args()

    rows, meta = load(args.db)
    tiers = [t for t in args.tiers.split(",") if t]
    if args.include_residential and "residential" not in tiers:
        tiers.append("residential")
    residential_excluded = 0 if args.include_residential else sum(1 for r in rows if r["tier"] == "residential")
    sections = {t: sorted([r for r in rows if r["tier"] == t], key=lambda r: -r["score"])[:args.per_tier] for t in tiers}
    totals = {t: sum(1 for r in rows if r["tier"] == t) for t in tiers}
    os.makedirs(args.out, exist_ok=True)
    stem = os.path.join(args.out, f"top_hosts_{meta['newest_day']}")
    write_csv(stem + ".csv", sections)
    write_pdf(stem + ".pdf", sections, totals, meta, args.marking, args.per_tier, residential_excluded, len(rows))
    print(json.dumps({"pdf": stem + ".pdf", "csv": stem + ".csv", "scored": len(rows),
                      "per_tier": {t: len(v) for t, v in sections.items()}, "totals": totals}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
