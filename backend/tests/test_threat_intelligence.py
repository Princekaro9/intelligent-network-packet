import json
from io import BytesIO

import pytest

from app.enrichment import threat_intelligence as ti


def test_private_address_never_calls_external_registry(monkeypatch) -> None:
    def unexpected_call(*args, **kwargs):
        raise AssertionError("Une adresse privée ne doit pas être envoyée.")

    monkeypatch.setattr(ti, "urlopen", unexpected_call)
    result = ti.enrich_ip("10.1.2.3")

    assert result["status"] == "non_enrichie"
    assert result["source"] == "local"


def test_public_address_returns_registry_facts(monkeypatch) -> None:
    ti._cache.clear()
    payload = {
        "name": "Example Network",
        "handle": "NET-EXAMPLE",
        "country": "US",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "entities": [{"vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]}],
    }

    class Response(BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    monkeypatch.setattr(ti, "urlopen", lambda *args, **kwargs: Response(json.dumps(payload).encode()))
    result = ti.enrich_ip("8.8.8.8")

    assert result["status"] == "enrichie"
    assert result["organizations"] == ["Example Org"]
    assert "pas une preuve" in result["interpretation"]
