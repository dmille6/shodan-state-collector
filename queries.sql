-- queries.sql — starter analytical queries for the exposure store.
--   duckdb store/exposure.duckdb
-- then paste any query below.
-- Views: observations, vulns (one row per CVE per observation; join on
-- (date, observation_id) — the same cached record can recur on several days), latest_observed (latest banner per ip:port:transport, all
-- time), exposure_status (latest_observed + status active/stale/gone by days
-- since seen), current_state (= exposure_status WHERE status = 'active', i.e.
-- seen in the last 14 days — "exposed right now"), lifecycle (first/last seen).
-- Data is PASSIVE and version-inferred — findings are LEADS TO VERIFY, not
-- incidents. vulns.verified = Shodan confirmed the CVE on the host (rare).

-- 1) Daily accounting: hosts + KEV-vuln hosts by sector tier (current picture)
SELECT cs.tier,
       count(*)                                        AS host_services,
       count(DISTINCT cs.ip)                           AS unique_hosts,
       count(DISTINCT CASE WHEN v.in_kev THEN cs.ip END) AS hosts_with_kev
FROM current_state cs
LEFT JOIN vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
GROUP BY cs.tier
ORDER BY hosts_with_kev DESC;

-- 2) Top actionable exposures right now: KEV-listed CVEs on gov/critical-infra
--    (verified first — Shodan confirmed it — then by exploit probability)
SELECT cs.tier, cs.ip, cs.org, cs.city, v.cve, v.verified, v.cvss, round(v.epss,3) AS epss
FROM current_state cs
JOIN vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
WHERE v.in_kev
  AND cs.tier IN ('critical_infrastructure','government','education')
ORDER BY v.verified DESC, v.epss DESC NULLS LAST, v.cvss DESC
LIMIT 25;

-- 3) NEW exposures on the most recent day (ip:port never seen before)
SELECT o.tier, o.ip, o.org, o.city, o.port, o.product
FROM observations o
JOIN lifecycle l ON l.ip = o.ip AND l.port = o.port AND l.transport = o.transport
WHERE o.date = (SELECT max(date) FROM observations)
  AND l.first_seen = o.date
ORDER BY o.tier;

-- 4) Longest-standing OPEN exposures (still present on the latest day) — dwell time
SELECT l.ip, l.port, l.transport, l.first_seen, l.last_seen, l.span_days, cs.tier, cs.org, cs.product
FROM lifecycle l
JOIN current_state cs ON cs.ip = l.ip AND cs.port = l.port AND cs.transport = l.transport
WHERE l.last_seen = (SELECT max(date) FROM observations)
ORDER BY l.span_days DESC, l.first_seen
LIMIT 25;

-- 5) Possible REMEDIATION: ip:port seen previously but absent on the latest day
SELECT l.ip, l.port, l.transport, l.first_seen, l.last_seen AS last_seen_before_gone
FROM lifecycle l
WHERE l.last_seen < (SELECT max(date) FROM observations)
ORDER BY l.last_seen DESC
LIMIT 25;

-- 6) Per-org rollup (attribution target list): hosts, KEV, worst EPSS
SELECT cs.org, cs.tier,
       count(DISTINCT cs.ip)                              AS hosts,
       count(DISTINCT CASE WHEN v.in_kev THEN v.cve END)  AS kev_cves,
       round(max(v.epss),3)                               AS worst_epss
FROM current_state cs
LEFT JOIN vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
GROUP BY cs.org, cs.tier
HAVING kev_cves > 0
ORDER BY kev_cves DESC
LIMIT 30;

-- 7) Internet-exposed ICS/SCADA (critical-infra deep dive)
SELECT date, ip, org, city, port, product
FROM observations
WHERE port IN (502,20000,47808,102,44818,1911,2404,789)
  AND date = (SELECT max(date) FROM observations)
ORDER BY org;


-- 8) Freshness accounting: how much of "latest observed" is actually current?
SELECT status, count(*) AS services, count(DISTINCT ip) AS hosts
FROM exposure_status GROUP BY status ORDER BY status;

-- 9) Who owns it? Certificate subject / SANs and HTTP Host beside the carrier org
SELECT ip, port, org, cert_org, cert_cn, cert_sans, http_host, tier
FROM current_state
WHERE cert_cn IS NOT NULL AND tier IN ('critical_infrastructure','government','education')
ORDER BY tier, cert_org
LIMIT 50;

-- 10) Appliance-first triage: exposed edge appliances on priority tiers, KEV+exploit first
SELECT a.tier, a.appliance, a.ip, a.port, a.org, a.product, a.http_title,
       count(DISTINCT CASE WHEN v.in_kev THEN v.cve END)                       AS kev_cves,
       count(DISTINCT CASE WHEN v.in_kev AND v.has_exploit THEN v.cve END)     AS kev_with_public_exploit
FROM appliance_exposure a
LEFT JOIN vulns v ON v.observation_id = a.observation_id AND v.date = a.date
WHERE a.tier IN ('critical_infrastructure','government','education')
GROUP BY ALL
ORDER BY kev_with_public_exploit DESC, kev_cves DESC, a.tier;

-- 11) Exploitable right now: KEV + public exploit/template (Metasploit/Nuclei), verified first
SELECT cs.tier, cs.ip, cs.port, cs.org, v.cve, v.verified, round(v.epss,3) AS epss
FROM current_state cs JOIN vulns v ON v.observation_id = cs.observation_id AND v.date = cs.date
WHERE v.in_kev AND v.has_exploit AND cs.tier IN ('critical_infrastructure','government','education')
ORDER BY v.verified DESC, v.epss DESC NULLS LAST LIMIT 50;

-- 12) IOC feed matches (free feeds, matched locally). Residential is aggregated, never listed.
SELECT tier, ioc_sources, count(DISTINCT ip) AS hosts FROM ioc_matches GROUP BY ALL ORDER BY hosts DESC;
SELECT ip, port, org, tier, ioc_sources FROM ioc_matches WHERE tier <> 'residential' ORDER BY tier;

-- 13) Registry attribution coverage (Phase 2 owner registry)
SELECT attr_method, attr_confidence, count(DISTINCT ip) AS hosts
FROM current_state GROUP BY ALL ORDER BY hosts DESC;
