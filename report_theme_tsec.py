#!/usr/bin/env python3
"""
report_theme_tsec.py — the TSEC field-report look for top_hosts_report.py.

Modelled on the unit's monthly honeynet report ("Four Seconds to Shell"):
dark navy pages, cyan / amber accents, Chakra Petch display type, IBM Plex
Mono text and data, letter-spaced eyebrow labels, numbered sections, big
stat tiles, and a plain-spoken editorial voice. Same page size as that deck.

Fonts: reference/fonts/*.ttf (Chakra Petch, IBM Plex Mono — OFL, fetched by
the first run of top_hosts_report from the Google Fonts repository). Falls
back to Helvetica/Courier if a face is missing, so the report always builds.
"""
import datetime as dt
import html
import os

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_DIR = os.path.join(SCRIPT_DIR, "reference", "fonts")
PAGE = (960.0, 1215.12)                       # the deck's page size (Chromium print)

# Palette lifted from the monthly report.
C = {"bg": "#060f1d", "bg2": "#091528", "bg3": "#0d1a2c", "panel": "#1e293a", "rule": "#1e293a",
     "text": "#f0f5f9", "muted": "#93a2b8", "dim": "#63748a", "cyan": "#21d3ed", "amber": "#f59e0a",
     "purple": "#7b3aec", "green": "#10b981", "red": "#ee4444", "pink": "#eb4799", "teal": "#0d9387"}
col = {k: colors.HexColor(v) for k, v in C.items()}
STRIPE = {"critical_infrastructure": C["red"], "government": C["cyan"], "education": C["purple"],
          "small_business": C["amber"], "unclassified": C["dim"]}
TIER_TITLE = {"critical_infrastructure": "Critical infrastructure", "government": "Government",
              "education": "Education", "small_business": "Business",
              "unclassified": "Unattributed carrier space", "out_of_state_gov": "Out-of-state government",
              "residential": "Residential"}


def _register():
    faces = {"Chakra-SemiBold": "ChakraPetch-SemiBold.ttf", "Chakra-Bold": "ChakraPetch-Bold.ttf",
             "Chakra-Medium": "ChakraPetch-Medium.ttf", "Plex": "IBMPlexMono-Regular.ttf",
             "Plex-Medium": "IBMPlexMono-Medium.ttf", "Plex-SemiBold": "IBMPlexMono-SemiBold.ttf",
             "Plex-Bold": "IBMPlexMono-Bold.ttf"}
    ok = {}
    for name, fn in faces.items():
        path = os.path.join(FONT_DIR, fn)
        try:
            pdfmetrics.registerFont(TTFont(name, path))
            ok[name] = name
        except Exception:
            ok[name] = "Helvetica-Bold" if "Chakra" in name or "Bold" in name else "Courier"
    return ok


def spaced(s, canvas=False):
    """Letter-spaced eyebrow, the way the deck sets its section labels.

    Paragraphs collapse runs of ordinary spaces, so letters are joined with
    no-break spaces and word gaps keep one breakable space; canvas text needs
    only plain spaces."""
    if canvas:
        return " ".join(s.upper())
    return " \u00a0 ".join("\u00a0".join(w) for w in s.upper().split())


def first_n(csv_text, n):
    return ", ".join(sorted({x for x in (csv_text or "").split(",") if x})[:n])


def owner_words(r):
    if r.get("attr_org") and r.get("attr_conf") in ("high", "medium"):
        return f"{r['attr_org']} · {r['attr_conf']} · {r['attr_method']}"
    return f"{r.get('org') or '?'} · operator label"


def write_pdf_tsec(path, sections, totals, meta, verify, marking, per_tier, residential_excluded, n_scored,
                   score_weights):
    F = _register()
    e = html.escape
    generated = dt.date.today().isoformat()

    body = ParagraphStyle("body", fontName=F["Plex"], fontSize=10.2, leading=15, textColor=col["muted"])
    body_w = ParagraphStyle("bodyw", parent=body, textColor=col["text"])
    eyebrow = ParagraphStyle("eyebrow", fontName=F["Plex-Medium"], fontSize=8.6, leading=11, textColor=col["muted"])
    eyebrow_c = ParagraphStyle("eyebrowc", parent=eyebrow, textColor=col["cyan"])
    h1 = ParagraphStyle("h1", fontName=F["Chakra-Bold"], fontSize=54, leading=58, textColor=col["text"])
    h2 = ParagraphStyle("h2", fontName=F["Chakra-SemiBold"], fontSize=30, leading=34, textColor=col["text"])
    h3 = ParagraphStyle("h3", fontName=F["Chakra-SemiBold"], fontSize=15, leading=19, textColor=col["text"])
    big = ParagraphStyle("big", fontName=F["Chakra-Bold"], fontSize=64, leading=66, textColor=col["cyan"])
    tile_n = ParagraphStyle("tilen", fontName=F["Chakra-Bold"], fontSize=26, leading=28, textColor=col["cyan"])
    tile_l = ParagraphStyle("tilel", fontName=F["Plex-Medium"], fontSize=7.6, leading=10, textColor=col["muted"])
    cell = ParagraphStyle("cell", fontName=F["Plex"], fontSize=8.4, leading=11, textColor=col["text"])
    cell_m = ParagraphStyle("cellm", parent=cell, textColor=col["muted"])
    small = ParagraphStyle("small", fontName=F["Plex"], fontSize=7.4, leading=9.6, textColor=col["dim"])
    th = ParagraphStyle("th", fontName=F["Plex-Medium"], fontSize=7.4, leading=9, textColor=col["muted"])

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(col["bg"])
        canvas.rect(0, 0, PAGE[0], PAGE[1], stroke=0, fill=1)
        canvas.setFillColor(col["amber"])
        canvas.setFont(F["Plex-Medium"], 8)
        canvas.drawString(0.6 * inch, PAGE[1] - 0.45 * inch, spaced(marking, canvas=True))
        canvas.setFillColor(col["dim"])
        canvas.setFont(F["Plex"], 8)
        canvas.drawString(0.6 * inch, 0.42 * inch, spaced("Louisiana exposure census · top exposed hosts by sector", canvas=True))
        canvas.drawRightString(PAGE[0] - 0.6 * inch, 0.42 * inch, f"{doc.page:02d}")
        canvas.setStrokeColor(col["rule"])
        canvas.setLineWidth(0.6)
        canvas.line(0.6 * inch, PAGE[1] - 0.6 * inch, PAGE[0] - 0.6 * inch, PAGE[1] - 0.6 * inch)
        canvas.restoreState()

    doc = SimpleDocTemplate(path, pagesize=PAGE, leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.85 * inch, bottomMargin=0.75 * inch,
                            title="Louisiana Top Exposed Hosts by Sector", author="LSP Cyber Crime Unit")
    W = PAGE[0] - 1.2 * inch
    story = []

    # ---------- cover ----------
    n_hosts = sum(len(v) for v in sections.values())
    still = sum(1 for v in (verify or {}).values() if v["currency"].get("kev_still_listed"))
    rans = sum(1 for v in (verify or {}).values() if v["risk"].get("ransomware_kev"))
    lic = sum(1 for v in (verify or {}).values() if v.get("licensed_flags"))
    story += [Spacer(1, 60),
              Paragraph(spaced("Louisiana exposure census · field report · " + meta["newest_day"]), eyebrow_c),
              Spacer(1, 26),
              Paragraph(f"{n_scored:,}", big),
              Paragraph(spaced(f"active hosts scored · {meta['days']} days of collection"), eyebrow),
              Spacer(1, 40),
              Paragraph("Exposed, reachable,<br/>and still there today.", h1),
              Spacer(1, 22),
              Paragraph(f"The {n_hosts} machines in this report are the most vulnerable currently observed hosts in "
                        f"each sector — {per_tier} per sector — ranked by verified and exploitable known-exploited "
                        f"CVEs, exposed industrial protocols, edge appliances, threat-feed hits and exposed admin "
                        f"services. Every one was re-checked on Shodan the day this was generated. Every one links "
                        f"to its Shodan page.", body_w),
              Spacer(1, 14),
              Paragraph("None of them were probed. Every row is a lead to verify by contacting the owner, not a "
                        "confirmed vulnerability: a CVE attached to a host is Shodan's inference from the software "
                        "version in the banner unless it is marked verified.", body),
              Spacer(1, 40)]
    tiles = [(f"{still}", "still show a KEV CVE on Shodan today"), (f"{rans}", "carry a KEV CVE tied to ransomware"),
             (f"{lic}", "flagged by licensed intelligence"), (f"{meta['honeypots']}", "honeypots excluded"),
             (f"{residential_excluded:,}", "residential hosts set aside")]
    story.append(_tiles(tiles, W, tile_n, tile_l))
    story.append(Spacer(1, 40))
    story.append(Paragraph(spaced("How it moves"), eyebrow_c))
    story.append(Spacer(1, 8))
    story.append(_flow(["Shodan sees a service", "The census records it nightly", "Evidence accumulates",
                        "Verification weighs it", "Someone gets a call"], W, F))
    story.append(Spacer(1, 40))
    story.append(Paragraph(spaced("In this report"), eyebrow_c))
    story.append(Spacer(1, 10))
    story.append(_overview(sections, totals, verify, F, th, cell, cell_m))
    story.append(PageBreak())

    # ---------- sections ----------
    for n, (tier, rows) in enumerate(sections.items(), 1):
        if not rows:
            continue
        hi = sum(1 for r in rows if r["kev_verified"] or r["kev_exploit"])
        ics = sum(1 for r in rows if r["ics"])
        ioc = sum(1 for r in rows if r.get("ioc"))
        v_r = sum(1 for r in rows if (verify or {}).get(r["ip"], {}).get("risk", {}).get("ransomware_kev"))
        v_l = sum(1 for r in rows if (verify or {}).get(r["ip"], {}).get("licensed_flags"))
        story += [Paragraph(f"{n:02d} &nbsp; {spaced(TIER_TITLE.get(tier, tier))}", eyebrow_c), Spacer(1, 10),
                  Paragraph(_section_headline(tier), h2), Spacer(1, 10),
                  Paragraph(_section_blurb(tier, totals.get(tier, 0)), body), Spacer(1, 18),
                  _tiles([(f"{len(rows)}", f"shown of {totals.get(tier, 0):,} active"),
                          (f"{hi}", "verified or exploitable KEV"), (f"{ics}", "ICS protocol exposed"),
                          (f"{ioc}", "on a threat feed"), (f"{v_r}", "KEV tied to ransomware"),
                          (f"{v_l}", "licensed intel flag")], W, tile_n, tile_l),
                  Spacer(1, 18)]
        data = [[Paragraph(spaced(h), th) for h in ("#", "host", "owner", "score", "evidence", "verification")]]
        for i, r in enumerate(rows, 1):
            v = (verify or {}).get(r["ip"])
            url = f"https://www.shodan.io/host/{r['ip']}"
            host = (f'<link href="{url}"><font color="{C["cyan"]}">{e(r["ip"])}</font></link><br/>'
                    f'<font color="{C["dim"]}" size="7">{e(r.get("city") or "")}'
                    f'{" · " if r.get("city") and r.get("asn") else ""}{e(r.get("asn") or "")}</font><br/>'
                    f'<link href="{url}"><font color="{C["dim"]}" size="7">shodan ↗</font></link>')
            owner = f'<font color="{C["text"]}">{e(owner_words(r))}</font>'
            if v and v["owner"].get("registrant"):
                owner += f'<br/><font color="{C["muted"]}" size="7.4">netblock {e(v["owner"]["registrant"])}</font>'
            if v and v["owner"].get("abuse_contacts"):
                owner += f'<br/><font color="{C["dim"]}" size="7.4">{e(", ".join(v["owner"]["abuse_contacts"][:2]))}</font>'
            names = first_n(r.get("hostnames"), 2) or ", ".join((v or {}).get("owner", {}).get("current_hostnames", [])[:2])
            if names:
                owner += f'<br/><font color="{C["dim"]}" size="7.4">{e(names)}</font>'
            ev = _evidence_html(r, v)
            ver = _verify_html(v)
            data.append([Paragraph(f'<font color="{C["dim"]}">{i:02d}</font>', cell), Paragraph(host, cell),
                         Paragraph(owner, cell),
                         Paragraph(f'<font color="{C["amber"]}" name="{F["Chakra-Bold"]}" size="15">{r["score"]:.0f}</font>', cell),
                         Paragraph(ev, cell), Paragraph(ver, cell_m)])
        widths = [0.35 * inch, 1.6 * inch, 2.7 * inch, 0.9 * inch, 3.4 * inch, W - 8.95 * inch]
        t = Table(data, colWidths=widths, repeatRows=1)
        st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, 0), 0.6, col["muted"]),
              ("LINEBELOW", (0, 1), (-1, -1), 0.4, col["rule"]),
              ("ROWBACKGROUNDS", (0, 1), (-1, -1), [col["bg"], col["bg2"]]),
              ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
              ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
              ("LINEBEFORE", (0, 1), (0, -1), 2.2, colors.HexColor(STRIPE.get(tier, C["dim"])))]
        t.setStyle(TableStyle(st))
        story.append(t)
        story.append(PageBreak())

    # ---------- method ----------
    w = score_weights
    story += [Paragraph(f"{len(sections) + 1:02d} &nbsp; {spaced('How to read this')}", eyebrow_c), Spacer(1, 10),
              Paragraph("Evidence first. Attribution second.<br/>Nothing here was touched.", h2), Spacer(1, 16)]
    cols3 = [
        [Paragraph(spaced("The score"), eyebrow), Spacer(1, 6),
         Paragraph(f"<b>{w['kev_verified']}</b> per KEV CVE Shodan verified on the host<br/>"
                   f"<b>{w['kev_exploit']}</b> per KEV CVE with a public Metasploit or Nuclei exploit<br/>"
                   f"<b>{w['kev']}</b> per other CISA KEV CVE (version-inferred)<br/>"
                   f"<b>{w['ioc']}</b> if the IP is on a threat feed<br/>"
                   f"<b>{w['ics']}</b> per exposed ICS protocol<br/>"
                   f"<b>{w['appliance']}</b> for an exposed edge appliance<br/>"
                   f"<b>{w['db_port']}</b> per exposed database, <b>{w['admin_port']}</b> per exposed admin service<br/>"
                   f"plus max EPSS × {w['epss']} and max CVSS", body)],
        [Paragraph(spaced("Verification"), eyebrow), Spacer(1, 6),
         Paragraph("<b>Louisiana</b> confidence is a vote count from Shodan's region, MaxMind, the ARIN netblock "
                   "registrant's state, a carrier metro code in reverse DNS or the netblock name, and the owner "
                   "registry. High = three or more agree.<br/><br/>"
                   "<b>Still listed</b> means the host was re-queried on Shodan the day this was built and at "
                   "least one of its KEV CVEs is on the current record; the last scan date is shown.<br/><br/>"
                   "<b>Ransomware-linked</b> is CISA's own flag on the KEV entry.", body)],
        [Paragraph(spaced("Owner and intelligence"), eyebrow), Spacer(1, 6),
         Paragraph("<b>Operator label</b> means only the carrier's org field is known; the customer behind the IP "
                   "is unattributed and needs analyst work before any notification. The ARIN netblock registrant "
                   "and abuse contact are shown under each owner.<br/><br/>"
                   "<b>Licensed intelligence</b> (GTI/VirusTotal, CrowdStrike, AbuseIPDB, OTX) was run only against "
                   "these hosts. A malware sample that <i>communicated with</i> a host means the sample reached out "
                   "to that address when detonated — infrastructure or a legitimate public server it contacted; "
                   "an analyst decides.<br/><br/>"
                   "Honeypots are excluded. Residential subscribers are reported to ISPs in aggregate, never by IP.", body)],
    ]
    t = Table([cols3], colWidths=[W / 3] * 3)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 18)]))
    story.append(t)
    story.append(Spacer(1, 30))
    story.append(Paragraph(f"Source: the exposure store (current_state joined to vulns on date and observation_id, "
                           f"appliance_exposure and ioc_matches views); owner from the Phase 2 registry generation; "
                           f"verification and enrichment from verify_hosts.py and enrich_licensed.py. Generated "
                           f"{generated} by top_hosts_report.py --theme tsec.", small))
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


# ---------- pieces ----------

def _tiles(items, width, n_style, l_style):
    cells = [[[Paragraph(n, n_style)], [Paragraph(spaced(l), l_style)]] for n, l in items]
    row = [Table(c, colWidths=[width / len(items) - 10]) for c in cells]
    for tbl in row:
        tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), col["bg3"]), ("LEFTPADDING", (0, 0), (-1, -1), 12),
                                 ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 12),
                                 ("BOTTOMPADDING", (0, 0), (-1, -1), 12), ("LINEABOVE", (0, 0), (-1, 0), 2, col["cyan"])]))
    outer = Table([row], colWidths=[width / len(items)] * len(items))
    outer.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 10)]))
    return outer


def _overview(sections, totals, verify, F, th, cell, cell_m):
    """Cover table: one line per sector with its key counts and the top lead."""
    e = html.escape
    head = [Paragraph(spaced(h), th) for h in ("", "sector", "shown / active", "verified or exploitable KEV",
                                                "ICS", "tied to ransomware", "licensed flag", "top lead")]
    data = [head]
    for n, (tier, rows) in enumerate(sections.items(), 1):
        if not rows:
            continue
        top = rows[0]
        v = (verify or {}).get(top["ip"], {})
        data.append([
            Paragraph(f'<font color="{C["cyan"]}">{n:02d}</font>', cell),
            Paragraph(f'<font color="{C["text"]}">{e(TIER_TITLE.get(tier, tier))}</font>', cell),
            Paragraph(f'{len(rows)} / {totals.get(tier, 0):,}', cell_m),
            Paragraph(str(sum(1 for r in rows if r["kev_verified"] or r["kev_exploit"])), cell_m),
            Paragraph(str(sum(1 for r in rows if r["ics"])), cell_m),
            Paragraph(str(sum(1 for r in rows if (verify or {}).get(r["ip"], {}).get("risk", {}).get("ransomware_kev"))), cell_m),
            Paragraph(str(sum(1 for r in rows if (verify or {}).get(r["ip"], {}).get("licensed_flags"))), cell_m),
            Paragraph(f'<font color="{C["cyan"]}">{e(top["ip"])}</font> <font color="{C["amber"]}">{top["score"]:.0f}</font>'
                      f'<br/><font color="{C["dim"]}" size="7.4">{e(owner_words(top))}</font>', cell),
        ])
    W = PAGE[0] - 1.2 * inch
    t = Table(data, colWidths=[0.4 * inch, 2.4 * inch, 1.3 * inch, 1.9 * inch, 0.6 * inch, 1.5 * inch, 1.2 * inch,
                               W - 9.3 * inch], repeatRows=1)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, 0), 0.6, col["muted"]),
                           ("LINEBELOW", (0, 1), (-1, -1), 0.4, col["rule"]),
                           ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return t


def _flow(steps, width, F):
    st = ParagraphStyle("flow", fontName=F["Chakra-SemiBold"], fontSize=11, leading=14, textColor=col["text"])
    arrow = ParagraphStyle("arrow", fontName=F["Plex"], fontSize=14, textColor=col["cyan"])
    cells = []
    for i, s in enumerate(steps):
        cells.append(Paragraph(s, st))
        if i < len(steps) - 1:
            cells.append(Paragraph("→", arrow))
    widths = []
    for i in range(len(cells)):
        widths.append(0.3 * inch if i % 2 else (width - 0.3 * inch * (len(steps) - 1)) / len(steps))
    t = Table([cells], colWidths=widths)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    return t


def _section_headline(tier):
    return {"critical_infrastructure": "The ones that hurt people if they stop.",
            "government": "State and local government, on the public internet.",
            "education": "Universities, colleges and school districts.",
            "small_business": "Businesses with a name on the door.",
            "unclassified": "Carrier space. Somebody is behind it."}.get(tier, TIER_TITLE.get(tier, tier))


def _section_blurb(tier, total):
    base = {"critical_infrastructure": "Healthcare, utilities, energy, oil and gas, ICS devices and emergency services. "
                                       "Most ICS exposures here sit on carrier space, which is why their owner still reads as a label.",
            "government": "Louisiana state agencies, parishes and cities. Attribution here is strongest: state domains and "
                          "curated address space name the owner outright.",
            "education": "Universities carry the most exploitable KEV CVEs of any sector, on well-attributed networks.",
            "small_business": "Commercial organisations with their own identity, plus a few municipalities the classifier "
                              "missed until verification named them.",
            "unclassified": "Hosts on carrier, cloud or transit networks with no customer identity yet. The owner is unknown; "
                            "attribution work comes before any notification."}.get(tier, "")
    return f"{base} {total:,} active hosts in this tier."


def _evidence_html(r, v):
    e = html.escape
    parts = []
    if r["kev_verified"]:
        parts.append(f'<font color="{C["red"]}"><b>{r["kev_verified"]} KEV verified by Shodan</b></font>')
    if r["kev_exploit"]:
        parts.append(f'<font color="{C["amber"]}"><b>{r["kev_exploit"]} KEV with public exploit</b></font>')
    if r["kev"] and not r["kev_verified"] and not r["kev_exploit"]:
        parts.append(f'<font color="{C["amber"]}">{r["kev"]} KEV, version-inferred</font>')
    elif r["kev"] > max(r["kev_verified"], r["kev_exploit"]):
        parts.append(f'<font color="{C["muted"]}">{r["kev"]} KEV total</font>')
    if r["ics"]:
        parts.append(f'<font color="{C["purple"]}"><b>{r["ics"]} ICS protocol{"s" if r["ics"] > 1 else ""} exposed</b></font>')
    if r.get("appliances"):
        parts.append(f'<font color="{C["teal"]}">{e(r["appliances"])}</font>')
    if r.get("ioc"):
        parts.append(f'<font color="{C["pink"]}"><b>threat feed: {e(r["ioc"])}</b></font>')
    if r["admin_ports"]:
        parts.append(f'<font color="{C["muted"]}">{r["admin_ports"]} admin service{"s" if r["admin_ports"] > 1 else ""}</font>')
    if r["db_ports"]:
        parts.append(f'<font color="{C["muted"]}">{r["db_ports"]} database service{"s" if r["db_ports"] > 1 else ""}</font>')
    if v and v["risk"].get("ransomware_kev"):
        parts.append(f'<font color="{C["red"]}"><b>ransomware-linked: {e(" ".join(v["risk"]["ransomware_kev"][:2]))}</b></font>')
    for f in (v or {}).get("licensed_flags") or []:
        parts.append(f'<font color="{C["pink"]}"><b>{e(f)}</b></font>')
    kevs = (r.get("kev_list") or "").split()
    line = " · ".join(parts)
    cv = f'{r["max_cvss"]:.1f}' if r.get("max_cvss") else "—"
    ep = f'{r["max_epss"]:.2f}' if r.get("max_epss") else "—"
    line += f'<br/><font color="{C["dim"]}" size="7.4">CVSS {cv} · EPSS {ep} · {r["services"]} services'
    prods = first_n(r.get("products"), 3)
    if prods:
        line += f" · {e(prods)}"
    line += "</font>"
    if kevs:
        line += f'<br/><font color="{C["dim"]}" size="7">{e(" ".join(kevs[:5]))}{" …" if len(kevs) > 5 else ""}</font>'
    return line


def _verify_html(v):
    e = html.escape
    if not v:
        return f'<font color="{C["dim"]}">not verified</font>'
    la, cur = v["louisiana"], v["currency"]
    conf_col = {"high": C["green"], "medium": C["amber"], "low": C["red"]}.get(la["confidence"], C["dim"])
    bits = [f'<font color="{conf_col}"><b>Louisiana {la["confidence"]}</b></font> '
            f'<font color="{C["dim"]}">({e(", ".join(la["votes_for"]) or "no independent vote")})</font>']
    metro = la.get("rdns_city") or la.get("netblock_city_code")
    if metro:
        bits.append(f"metro {e(metro)}")
    if cur.get("shodan_last_update"):
        bits.append(f"scanned {e(str(cur['shodan_last_update'])[:10])}")
    if cur.get("kev_still_listed") is not None:
        n_s = len(cur["kev_still_listed"] or []); n_g = len(cur["kev_no_longer_listed"] or [])
        if n_s + n_g:
            colr = C["green"] if n_s else C["dim"]
            bits.append(f'<font color="{colr}">KEV still listed {n_s}/{n_s + n_g}</font>')
    if cur.get("dwell_days") is not None:
        bits.append(f"visible {cur['dwell_days']}d")
    if v["risk"].get("cert_expired"):
        bits.append(f'<font color="{C["amber"]}">cert expired</font>')
    pd = v["owner"].get("passive_dns") or []
    if pd:
        bits.append(f'<font color="{C["dim"]}">pDNS {e(", ".join(pd[:2]))}</font>')
    return "<br/>".join(bits)
