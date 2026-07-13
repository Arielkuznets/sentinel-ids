import ipaddress
from pathlib import Path

import geoip2.database


def _is_public(ip: str | None) -> bool:
    """True only for a globally routable address – private and loopback ranges are not places."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:      # not an IP at all
        return False


class GeoIPResolver:
    """Maps a public IP to a country and city from a local MaxMind GeoLite2 file.

    No API and no network: the .mmdb is a trie over IP prefixes that the reader
    memory-maps, so a lookup walks the address bit by bit and the 63MB file never
    lands in the heap. The reader is injected, and from_path() hands back a
    disabled resolver when the file is missing – the database is a gitignored
    asset, absent on a fresh clone, so that has to be a state and not a crash.
    """

    def __init__(self, reader: geoip2.database.Reader | None = None):
        self._reader = reader

    @classmethod
    def from_path(cls, database_path: str | None) -> "GeoIPResolver":
        if not database_path or not Path(database_path).is_file():
            return cls(None)
        return cls(geoip2.database.Reader(database_path))

    def lookup(self, ip: str | None) -> dict[str, str | None] | None:
        """Where `ip` is, or None when there is nothing to say about it.

        Every unknown collapses to one None – no database, no address, an address
        with no location, one the database never heard of – so each UI has a single
        empty case to render. Other failures are swallowed too: geo is decoration,
        never a reason to lose an alert. city alone stays None where the database
        knows the country but not the city (anycast, e.g. 8.8.8.8).
        """
        if self._reader is None or not _is_public(ip):
            return None
        try:
            response = self._reader.city(ip)
        except Exception:
            return None
        if response.country.name is None:
            return None
        return {"country": response.country.name, "city": response.city.name}
