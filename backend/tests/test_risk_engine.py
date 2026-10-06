from app.analysis.risk_engine import analyze_observations


def test_no_alert_is_not_reported_as_a_safe_network() -> None:
    result = analyze_observations(
        [{"protocol": "TCP", "packet_length_bytes": 60}], [], []
    )

    assert result["risk"]["score"] == 0
    assert "Aucun signal détecté" in result["risk"]["label"]
    assert "ne certifie pas" in result["interpretations"][0]
    assert result["facts_observed"][0].startswith("1 paquet")


def test_alert_is_explicitly_a_heuristic_and_creates_a_hypothesis() -> None:
    alert = {"rule_name": "tcp_multiport_scan", "title": "Ports multiples"}
    result = analyze_observations([], [], [alert])

    assert result["risk"]["score"] == 45
    assert result["risk"]["label"] == "À examiner"
    assert "pas une attaque confirmée" in result["interpretations"][0]
    assert result["hypotheses"]
