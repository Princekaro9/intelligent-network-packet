"""Routes d'analyse explicable et d'enrichissement externe."""

from __future__ import annotations

import ipaddress
import logging

from fastapi import APIRouter, HTTPException, Query

from app.analysis.risk_engine import analyze_observations
from app.capture.packet_capture import capture_manager
from app.enrichment.threat_intelligence import EnrichmentUnavailable, enrich_ip

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Analyse"])


@router.get("/analysis")
def get_analysis() -> dict:
    """Produit une synthèse vérifiable de l'échantillon récent."""
    return analyze_observations(
        capture_manager.get_recent_packets(200),
        capture_manager.get_recent_flows(500),
        capture_manager.get_recent_alerts(200),
    )


@router.get("/enrichment/ip")
def get_ip_enrichment(address: str = Query(min_length=2, max_length=45)) -> dict:
    """Interroge RDAP pour une adresse publique, à la demande."""
    try:
        ipaddress.ip_address(address)
        return enrich_ip(address)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Adresse IP invalide.") from error
    except EnrichmentUnavailable as error:
        logger.info("Enrichissement RDAP indisponible (%s).", type(error).__name__)
        raise HTTPException(status_code=503, detail=str(error)) from error
