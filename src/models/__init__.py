"""
models — Estruturas de dados centrais do SIEM.

Enumerações e dataclasses que representam:
  - Eventos de acesso (AccessEvent)
  - Resultados de análise (AnalysisResult)
  - Tipos de ataque e níveis de ameaça
  - Dados de geolocalização (GeoInfo)
"""

from src.models.event import (
    AccessEvent,
    AnalysisResult,
    AttackType,
    GeoInfo,
    ThreatLevel,
)

__all__ = [
    "ThreatLevel",
    "AttackType",
    "GeoInfo",
    "AccessEvent",
    "AnalysisResult",
]
