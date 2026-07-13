"""Unit tests for the GeoIPResolver.

The resolver is driven by a fake reader, so these tests never need the 63MB
GeoLite2 file - which is gitignored and absent on a fresh clone. One test does
use the real database, and skips itself when it is not installed.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.alerts.geoip import GeoIPResolver

_REAL_DB = Path(__file__).resolve().parent.parent / "data" / "GeoLite2-City.mmdb"


class _FakeReader:
    """Answers with a fixed place, and records what it was asked."""

    def __init__(self, country="Israel", iso="IL", city="Tel Aviv"):
        self.asked: list[str] = []
        self._response = SimpleNamespace(
            country = SimpleNamespace(name=country, iso_code=iso),
            city    = SimpleNamespace(name=city),
        )

    def city(self, ip):
        self.asked.append(ip)
        return self._response


class _NotFoundReader:
    def city(self, ip):
        raise LookupError("address not in database")


def test_public_ip_resolves_to_country_and_city():
    resolver = GeoIPResolver(_FakeReader())
    assert resolver.lookup("8.8.8.8") == {"country": "Israel", "iso": "IL", "city": "Tel Aviv"}


def test_country_without_a_city_keeps_the_city_empty():
    resolver = GeoIPResolver(_FakeReader(country="United States", iso="US", city=None))
    assert resolver.lookup("8.8.8.8") == {"country": "United States", "iso": "US", "city": None}


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.10", "10.0.0.5", "169.254.1.1",
                                None, "", "not-an-ip"])
def test_addresses_with_no_location_are_never_looked_up(ip):
    reader   = _FakeReader()
    resolver = GeoIPResolver(reader)
    assert resolver.lookup(ip) is None
    assert reader.asked == []


def test_an_address_the_database_does_not_know_is_not_an_error():
    resolver = GeoIPResolver(_NotFoundReader())
    assert resolver.lookup("8.8.8.8") is None


def test_a_missing_database_disables_the_resolver():
    resolver = GeoIPResolver.from_path("data/there-is-no-such-file.mmdb")
    assert resolver.lookup("8.8.8.8") is None


def test_no_path_configured_disables_the_resolver():
    assert GeoIPResolver.from_path(None).lookup("8.8.8.8") is None


@pytest.mark.skipif(not _REAL_DB.is_file(), reason="GeoLite2 database not installed")
def test_the_real_database_places_googles_resolver_in_the_united_states():
    resolver = GeoIPResolver.from_path(_REAL_DB.as_posix())
    geo = resolver.lookup("8.8.8.8")
    assert geo["country"] == "United States"
    assert geo["iso"] == "US"
    assert geo["city"] is None      # anycast: a country, no city
