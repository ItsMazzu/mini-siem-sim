"""
models/event.py — Modelos de dados centrais do SIEM Simulator.

Define as estruturas imutáveis que trafegam pelo sistema:
  - AccessEvent   : evento bruto lido do CSV / entrada manual
  - GeoInfo       : dados de geolocalização do IP
  - AnalysisResult: resultado completo da análise de um evento
  - ThreatLevel   : enumeração de nível de ameaça
  - AttackType    : enumeração de tipo de ataque detectado
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List


# ─────────────────────────────────────────────
# Enumerações
# ─────────────────────────────────────────────

class ThreatLevel(Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(Enum):
    NORMAL              = "Acesso Normal"
    SUSPICIOUS          = "Comportamento Suspeito"
    BRUTE_FORCE         = "Força Bruta"
    DICTIONARY_ATTACK   = "Ataque de Dicionário"
    PORT_SCAN           = "Varredura de Portas"
    CREDENTIAL_STUFFING = "Credential Stuffing"
    DOS_ATTEMPT         = "Tentativa de DoS"
    SQL_INJECTION       = "Injeção SQL"


# ─────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────

@dataclass
class GeoInfo:
    """Dados de geolocalização retornados pela API ip-api.com."""
    country:  str   = "Desconhecido"
    region:   str   = "Desconhecido"
    city:     str   = "Desconhecido"
    isp:      str   = "Desconhecido"
    org:      str   = "Desconhecido"
    lat:      float = 0.0
    lon:      float = 0.0
    timezone: str   = "Desconhecido"


@dataclass
class AccessEvent:
    """
    Representa um único evento de acesso/tentativa registrado no log.

    Campos obrigatórios
    -------------------
    ip        : endereço IP de origem (já validado pelo parser)
    timestamp : data/hora do evento
    attempts  : número de tentativas consecutivas neste evento

    Campos opcionais (padrão vazio/falso)
    --------------------------------------
    ports_tried    : lista de portas distintas que foram testadas
    usernames_tried: lista de nomes de usuário testados
    success        : True se o atacante conseguiu acesso ao sistema
    user_agent     : cabeçalho User-Agent da requisição
    payload_sample : amostra do payload da requisição (para detectar SQLi etc.)
    """
    ip:              str
    timestamp:       datetime
    attempts:        int
    ports_tried:     List[int] = field(default_factory=list)
    usernames_tried: List[str] = field(default_factory=list)
    success:         bool      = False
    user_agent:      str       = ""
    payload_sample:  str       = ""


@dataclass
class AnalysisResult:
    """Resultado completo da análise de um AccessEvent."""
    event:              AccessEvent
    geo_info:           GeoInfo
    threat_score:       int          # 0–100
    threat_level:       ThreatLevel
    attack_type:        AttackType
    intrusion_detected: bool
    details:            List[str] = field(default_factory=list)
    recommendations:    List[str] = field(default_factory=list)
    analyzed_at:        datetime  = field(default_factory=datetime.now)
