"""
detector — Pipeline de análise de ameaças de IP.

Etapas de processamento:
  1. Geolocalização (geo_locator): Recupera dados geográficos do IP
  2. Classificação de ataque (attack_classifier): Identifica o tipo de ataque
  3. Pontuação de ameaça (threat_scorer): Calcula risco (0-100) e nível
  4. Orquestração (ip_analyzer): Coordena todo o pipeline

Funções principais:
  - get_geo_info: Obtém geolocalização de um IP
  - classify_attack: Classifica o tipo de ataque
  - calculate_threat_score: Calcula a pontuação de risco
  - get_threat_level: Mapeia pontuação para nível (LOW/MEDIUM/HIGH/CRITICAL)
  - analyze_from_csv: Processa arquivo CSV completo
  - analyze_single_ip: Analisa um IP individual
"""

from src.detector.attack_classifier import classify_attack
from src.detector.geo_locator import get_geo_info
from src.detector.ip_analyzer import analyze_from_csv, analyze_single_ip
from src.detector.threat_scorer import (
    calculate_threat_score,
    get_recommendations,
    get_threat_level,
)

__all__ = [
    "get_geo_info",
    "classify_attack",
    "calculate_threat_score",
    "get_threat_level",
    "get_recommendations",
    "analyze_from_csv",
    "analyze_single_ip",
]
