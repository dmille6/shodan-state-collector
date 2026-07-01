-- queries.sql — starter analytical queries for the exposure store.
--   duckdb store/exposure.duckdb
-- then paste any query below. Views: observations, vulns, current_state, lifecycle.
-- Data is PASSIVE and version-inferred — findings are LEADS TO VERIFY, not incidents.

-- 1) Daily accounting: hosts + KEV-vuln hosts by sector tier (current picture)
SELECT cs.tier,
       count(*)                                        AS host_services,
       count(DISTINCT cs.ip)                           AS unique_hosts,
       count(DISTINCT CASE WHEN v.in_kev THEN cs.ip END) AS hosts_with_kev
FROM current_state cs
LEFT JOIN vulns v ON v.ip = cs.ip AND v.port = cs.port AND v.date = cs.date
GROUP BY cs.tier
ORDER BY hosts_with_kev DESC;

-- 2) Top actionable exposures right now: KEV-listed CVEs on gov/critical-infra
SELECT cs.tier, cs.ip, cs.org, cs.city, v.cve, v.cvss, round(v.epss,3) AS epss
FROM current_state cs
JOIN vulns v ON v.ip = cs.ip AND v.port = cs.port AND v.date = cs.date
WHERE v.in_kev
  AND cs.tier IN ('critical_infrastructure','government','education')
ORDER BY v.epss DESC NULLS LAST, v.cvss DESC
LIMIT 25;

-- 3) NEW exposures on the most recent day (ip:port never seen before)
SELECT o.tier, o.ip, o.org, o.city, o.port, o.product
FROM observations o
JOIN lifecycle l ON l.ip = o.ip AND l.port = o.port
WHERE o.date = (SELECT max(date) FROM observations)
  AND l.first_seen = o.date
ORDER BY o.tier;

-- 4) Longest-standing OPEN exposures (still present on the latest day) — dwell time
SELECT l.ip, l.port, l.first_seen, l.last_seen, l.span_days, cs.tier, cs.org, cs.product
FROM lifecycle l
JOIN current_state cs ON cs.ip = l.ip AND cs.port = l.port
WHERE l.last_seen = (SELECT max(date) FROM observations)
ORDER BY l.span_days DESC, l.first_seen
LIMIT 25;

-- 5) Possible REMEDIATION: ip:port seen previously but absent on the latest day
SELECT l.ip, l.port, l.first_seen, l.last_seen AS last_seen_before_gone
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
LEFT JOIN vulns v ON v.ip = cs.ip AND v.port = cs.port AND v.date = cs.date
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
