#!/usr/bin/env python3
"""Generate a sendable exposure-notification advisory (PDF) for Ochsner from the
pre-extracted ochsner.json dataset. Passive OSINT; leads to verify."""
import json
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

SRC = sys.argv[1] if len(sys.argv) > 1 else "ochsner.json"
OUT = sys.argv[2] if len(sys.argv) > 2 else "reports/Ochsner_Exposure_Notification.pdf"
DATE = sys.argv[3] if len(sys.argv) > 3 else "2026-07-05"
d = json.load(open(SRC))
hosts, services, days, first_seen, last_seen, asn = d["summary"]

NAVY = colors.HexColor("#1f3a5f")
AMBER = colors.HexColor("#b8860b")
LIGHT = colors.HexColor("#eef2f7")
ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], textColor=NAVY, fontSize=13, spaceBefore=14, spaceAfter=6)
BODY = ParagraphStyle("Body", parent=ss["Normal"], fontSize=9.5, leading=13, spaceAfter=6)
SMALL = ParagraphStyle("Small", parent=ss["Normal"], fontSize=7.5, leading=9)
BANNER = ParagraphStyle("Banner", parent=ss["Normal"], fontSize=9, textColor=colors.white,
                        alignment=TA_CENTER, fontName="Helvetica-Bold")
TITLE = ParagraphStyle("Title", parent=ss["Title"], textColor=NAVY, fontSize=17, leading=20)


def banner(txt):
    t = Table([[Paragraph(txt, BANNER)]], colWidths=[7.0 * inch])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), AMBER),
                           ("TOPPADDING", (0, 0), (-1, -1), 4),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return t


story = []
story.append(banner("TLP:AMBER  //  FOR OFFICIAL USE ONLY  //  CONTAINS SENSITIVE SECURITY INFORMATION"))
story.append(Spacer(1, 10))
story.append(Paragraph("Cybersecurity Exposure Notification", TITLE))
story.append(Paragraph("Internet-Facing Assets Attributed to Ochsner Clinic Foundation (AS63103)", H1))
story.append(HRFlowable(width="100%", color=NAVY, thickness=1.2, spaceAfter=8))

CELL = ParagraphStyle("Cell", parent=ss["Normal"], fontSize=8.5, leading=11)
def cell(txt): return Paragraph(txt, CELL)
meta = [
    ["Date issued:", cell(DATE), "Reference:", cell("LA-EXP-2026-0705-OCHSNER")],
    ["From:", cell("[ISSUING UNIT — e.g. LA State Police Cyber Crime Unit]"),
     "Method:", cell("Passive OSINT (Shodan); no active scanning")],
    ["To:", cell("Ochsner Clinic Foundation, via [Health-ISAC / MS-ISAC / State CISO]"),
     "Classification:", cell("TLP:AMBER / FOUO")],
    ["Point of contact:", cell("[NAME, EMAIL, PHONE]"),
     "Window:", cell(f"{first_seen} to {last_seen}")],
]
mt = Table(meta, colWidths=[1.0 * inch, 2.9 * inch, 0.95 * inch, 2.15 * inch])
mt.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8.5), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TEXTCOLOR", (0, 0), (0, -1), NAVY), ("TEXTCOLOR", (2, 0), (2, -1), NAVY),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey), ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.white)]))
story.append(mt)
story.append(Spacer(1, 4))

story.append(Paragraph("Purpose", H1))
story.append(Paragraph(
    f"This is a courtesy defensive notification. Through routine passive analysis of publicly available "
    f"internet-scan data, we identified <b>{hosts} internet-facing hosts</b> ({services} services) that "
    f"attribute to Ochsner Clinic Foundation's registered network (<b>{asn}</b>). Several present as "
    f"remote-access / network-edge infrastructure (VPN portals, F5 BIG-IP, appliance management interfaces). "
    f"These assets were observed on every collection day across the {first_seen} to {last_seen} window, "
    f"indicating persistent exposure. We are sharing this so your team can verify configuration and patch "
    f"status. <b>This is not an assertion of compromise or of any confirmed vulnerability.</b>", BODY))

story.append(Paragraph("Methodology and Important Limitations", H1))
for t in [
    "<b>Passive only.</b> Findings derive entirely from a third-party internet-scan index (Shodan). "
    "<b>No systems belonging to Ochsner were scanned, probed, or accessed</b> in producing this notice.",
    "<b>Leads to verify, not confirmed vulnerabilities.</b> Reported software/CVE associations are inferred "
    "from advertised banners/versions and may be inaccurate or already remediated. Exposure of a service is "
    "not evidence that it is vulnerable.",
    "<b>Appliance risk is likely UNDER-stated.</b> Scan data frequently cannot read firmware versions on "
    "VPN/firewall/load-balancer appliances (e.g. F5 BIG-IP), so known-exploited CVEs for those devices may "
    "not appear below even where relevant. The <b>presence</b> of an exposed management/VPN interface is the "
    "item to verify, independent of any CVE mapping.",
    "<b>Snapshot.</b> Data reflects the observation window above and may not represent current state.",
]:
    story.append(Paragraph("• " + t, BODY))

story.append(Paragraph("Summary of Observations", H1))
summ = [["Metric", "Value"],
        ["Attributed hosts (unique IPs)", str(hosts)],
        ["Distinct services (IP:port)", str(services)],
        ["Registered network", f"{asn} (Ochsner Clinic Foundation)"],
        ["Geography", ", ".join(f"{c} ({n})" for c, n in d["cities"])],
        ["Observation window", f"{first_seen} to {last_seen} (seen all {days} collection days)"],
        ["Priority items (edge/appliance/SNMP)", str(len(d["appliances"]))]]
st = Table(summ, colWidths=[2.6 * inch, 4.4 * inch])
st.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
story.append(st)

story.append(Paragraph("Priority Items for Verification", H1))
story.append(Paragraph(
    "The services below are internet-exposed remote-access / management / appliance interfaces (F5 BIG-IP, "
    "SSL-VPN-style HTTPS ports, and SNMP). For a healthcare environment these warrant priority review: confirm "
    "the device firmware is current against the vendor's advisories (for F5 BIG-IP, e.g. CVE-2022-1388 and "
    "CVE-2023-46747), confirm the interface is intended to be internet-facing, and restrict management planes "
    "to trusted networks. SNMP (port 161) exposure should be closed or restricted as it can disclose device "
    "configuration.", BODY))


def make_table(rows, headers, widths, fontsize=7.2):
    data_rows = [headers] + rows
    t = Table(data_rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), fontsize),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    return t


appl = sorted(d["appliances"], key=lambda r: (r[1], str(r[0])))
appl_rows = [[str(ip), str(port), str(prod)[:34], str(city)] for ip, port, prod, city in appl]
story.append(Spacer(1, 4))
story.append(make_table(appl_rows, ["IP address", "Port", "Service / product", "City"],
                        [1.5 * inch, 0.7 * inch, 3.0 * inch, 1.8 * inch]))

story.append(Paragraph("Recommended Actions (defensive)", H1))
for t in [
    "Verify current firmware/patch level of all exposed appliances against the vendor's security advisories.",
    "Confirm each internet-facing management/VPN interface is intended to be public; restrict or place behind MFA/VPN where not.",
    "Close or restrict exposed SNMP (161) and any non-essential high-port HTTPS management services.",
    "Cross-check these hosts against your asset inventory to catch shadow/forgotten systems.",
    "No action is requested of any third party against these hosts; verification should be performed by the asset owner.",
]:
    story.append(Paragraph("• " + t, BODY))

story.append(Paragraph("Appendix A — Full Observed Asset Inventory", H1))
story.append(Paragraph(f"All {services} observed services (IP:port) attributed to {asn}. "
                       "“Days” = number of collection days the service was observed (max "
                       f"{days}).", SMALL))
story.append(Spacer(1, 3))
inv_rows = [[str(ip), str(port), str(prod)[:30], str(city), str(dseen), str(ls)]
            for ip, port, prod, city, dseen, ls in d["inventory"]]
story.append(make_table(inv_rows, ["IP address", "Port", "Product", "City", "Days", "Last seen"],
                        [1.25 * inch, 0.55 * inch, 2.1 * inch, 1.35 * inch, 0.45 * inch, 0.9 * inch], 6.8))

story.append(Spacer(1, 10))
story.append(HRFlowable(width="100%", color=colors.grey, thickness=0.5, spaceAfter=6))
story.append(Paragraph(
    "<b>Handling:</b> TLP:AMBER — recipients may share only with members of their own organization and "
    "clients/constituents on a need-to-know basis to act on the information. This document contains sensitive "
    "security information about a named organization; protect accordingly. Provided as a good-faith defensive "
    "courtesy by [ISSUING UNIT]; it confers no warranty and imposes no obligation. Questions: [CONTACT].", SMALL))


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(AMBER)
    canvas.drawCentredString(letter[0] / 2, 0.35 * inch, "TLP:AMBER // FOR OFFICIAL USE ONLY")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(letter[0] - 0.6 * inch, 0.35 * inch, f"Page {doc.page}")
    canvas.restoreState()


doc = SimpleDocTemplate(OUT, pagesize=letter, topMargin=0.55 * inch, bottomMargin=0.6 * inch,
                        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                        title="Ochsner Exposure Notification (TLP:AMBER)")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(f"Wrote {OUT}")
