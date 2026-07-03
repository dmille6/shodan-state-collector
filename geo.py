#!/usr/bin/env python3
"""
geo.py — independent MaxMind geolocation gate.

We do NOT trust Shodan's location field for scoping (its state:LA filter has
been observed to fail and return worldwide hosts). Instead we look each IP up in
a local MaxMind City database and keep a host only if MaxMind independently
places it in the target US state.

Requires a MaxMind *City* database (has US state subdivisions), e.g.
reference/GeoLite2-City.mmdb or reference/GeoIP2-City.mmdb. Path is configurable
via GEOIP_DB in .env; if unset, the first *.mmdb under reference/ is used.
"""
import glob
import os

import geoip2.database
import geoip2.errors

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def find_db(path=None):
    """Resolve the .mmdb path: explicit arg > $GEOIP_DB > first in reference/."""
    cand = path or os.environ.get("GEOIP_DB")
    if cand and os.path.isfile(cand):
        return cand
    hits = sorted(glob.glob(os.path.join(SCRIPT_DIR, "reference", "*.mmdb")))
    return hits[0] if hits else None


class GeoGate:
    """Keep-if-in-target-state gate backed by a MaxMind City DB.

    Reader is memory-mapped, so lookups are microseconds and safe to reuse across
    a whole collection run. Not thread-safe; use one per process.
    """

    def __init__(self, db_path=None, country="US", region="LA"):
        resolved = find_db(db_path)
        if not resolved:
            raise FileNotFoundError(
                "No MaxMind .mmdb found (set GEOIP_DB or drop a City DB in reference/)")
        self.db_path = resolved
        self.country = country
        self.region = region
        self.reader = geoip2.database.Reader(resolved)

    def locate(self, ip):
        """Return (country_iso, subdivision_iso) or (None, None) if unknown."""
        try:
            r = self.reader.city(ip)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None, None
        sub = r.subdivisions.most_specific.iso_code if r.subdivisions else None
        return r.country.iso_code, sub

    def in_target(self, ip):
        cc, sub = self.locate(ip)
        return cc == self.country and sub == self.region

    def keep(self, ip, shodan_country=None, shodan_region=None):
        """Robust keep decision: drop only on POSITIVE off-target evidence.

        - MaxMind confirms target state           -> keep
        - MaxMind confidently elsewhere (foreign,
          or a *different* US state)               -> drop
        - MaxMind ambiguous (IP unknown, or US with
          no subdivision — common in GeoLite2)     -> defer to Shodan's own fields

        This removes worldwide/other-state pollution WITHOUT discarding real
        target-state hosts that the free DB can't pin to a subdivision."""
        cc, sub = self.locate(ip)
        if cc == self.country and sub == self.region:
            return True
        if cc is not None and (cc != self.country or (sub is not None and sub != self.region)):
            return False
        # Ambiguous — trust what Shodan reported for this banner.
        return shodan_country == self.country and shodan_region == self.region

    def close(self):
        self.reader.close()


if __name__ == "__main__":
    # Quick self-test / spot-check: geo.py <ip> [ip ...]
    import sys
    g = GeoGate()
    print(f"DB: {g.db_path}  target: {g.country}/{g.region}")
    for ip in sys.argv[1:]:
        cc, sub = g.locate(ip)
        print(f"  {ip:40s} -> {cc}/{sub}  keep={cc==g.country and sub==g.region}")
