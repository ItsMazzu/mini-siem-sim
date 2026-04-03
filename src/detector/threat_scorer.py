"""
detector/threat_scorer.py — Motor de pontuação de ameaças (0–100).

Sistema de pontuação por soma de fatores ponderados:

  Fator                          | Pontos máx.
  -------------------------------|------------
  Volume de tentativas           |    40
  Tipo de ataque                 |    40
  IP em blacklist conhecida      |    25
  Intrusão bem-sucedida          |    20
  Payload malicioso              |    15
  ISP/Org suspeito (VPN/Tor/etc) |    10
  Variedade de portas            |    10
  Variedade de usernames         |    10
  IP privado (bônus interno)     |   −10

  Cap: 100 pontos (score = min(soma, 100))

ThreatLevel por faixa de score:
  LOW      :  0–29
  MEDIUM   : 30–54
  HIGH     : 55–79
  CRITICAL : 80–100
"""

from typing import List, Tuple

from src.models.event import AccessEvent, AttackType, ThreatLevel
from src.utils.validator import is_private_ip

# ─────────────────────────────────────────────
# Dados de ameaças conhecidas
# ─────────────────────────────────────────────

# IPs com histórico documentado de atividade maliciosa / scanners conhecidos.
# Fontes: Shodan, AbuseIPDB, listas públicas de exit nodes Tor.
BLACKLISTED_IPS: set = {
    "185.220.101.45",   # Tor exit node — CCC Germany
    "185.220.101.47",   # Tor exit node
    "89.248.167.131",   # Shodan scanner (AS286)
    "89.248.165.134",   # Shodan scanner
    "193.32.162.157",   # Scanner registrado no AbuseIPDB
    "45.33.32.156",     # nmap.scanme.org — alvo oficial, mas fonte de scans
    "198.20.69.74",     # Shodan scanner (AS20473)
    "198.20.69.98",     # Shodan scanner
    "162.247.74.74",    # Tor exit node — EFF
    "162.247.74.200",   # Tor exit node — EFF
    "212.47.235.82",    # Registrado em blacklists europeias
    "194.165.16.11",    # Frequente em relatórios de brute-force SSH
    "80.82.77.139",     # ZMap/Shodan scanner
    "80.82.77.33",      # ZMap/Shodan scanner
}

# Palavras-chave em ISP/Org que indicam infraestrutura frequentemente
# usada em ataques: VPNs comerciais, proxies, datacenters anônimos.
_SUSPICIOUS_ISP_KEYWORDS: List[str] = [
    "tor", "vpn", "proxy", "anonymous", "bulletproof",
    "hosting", "datacenter", "vps", "colocation",
    "serverius", "frantech", "leaseweb",
]

# Pontuação base por tipo de ataque
_ATTACK_SCORES = {
    AttackType.NORMAL:              0,
    AttackType.SUSPICIOUS:         10,
    AttackType.BRUTE_FORCE:        20,
    AttackType.PORT_SCAN:          20,
    AttackType.DICTIONARY_ATTACK:  25,
    AttackType.CREDENTIAL_STUFFING:30,
    AttackType.DOS_ATTEMPT:        35,
    AttackType.SQL_INJECTION:      40,
}


# ─────────────────────────────────────────────
# Funções públicas
# ─────────────────────────────────────────────

def calculate_threat_score(
    event: AccessEvent,
    attack_type: AttackType,
    isp: str = "",
) -> Tuple[int, List[str]]:
    """
    Calcula a pontuação de ameaça (0–100) e retorna os indicadores detectados.

    Parâmetros
    ----------
    event       : evento de acesso analisado
    attack_type : tipo de ataque já classificado
    isp         : string ISP/Org retornada pela geolocalização

    Retorna
    -------
    (score: int, details: List[str])
    """
    score:   int       = 0
    details: List[str] = []

    # ── 1. Volume de tentativas (0–40 pts) ──────────────────────────
    attempts = event.attempts
    if attempts >= 500:
        score += 40
        details.append(f"Volume extremo de tentativas: {attempts}")
    elif attempts >= 100:
        score += 30
        details.append(f"Alto volume de tentativas: {attempts}")
    elif attempts >= 50:
        score += 20
        details.append(f"Volume elevado de tentativas: {attempts}")
    elif attempts >= 10:
        score += 10
        details.append(f"Múltiplas tentativas detectadas: {attempts}")
    elif attempts > 3:
        score += 5
        details.append(f"Tentativas repetidas: {attempts}")

    # ── 2. Tipo de ataque (0–40 pts) ────────────────────────────────
    attack_bonus = _ATTACK_SCORES.get(attack_type, 0)
    if attack_bonus > 0:
        score += attack_bonus
        details.append(f"Tipo de ataque classificado: {attack_type.value}")

    # ── 3. IP em blacklist (+25 pts) ────────────────────────────────
    if event.ip in BLACKLISTED_IPS:
        score += 25
        details.append("IP presente em blacklist de ameaças conhecidas")

    # ── 4. Intrusão bem-sucedida (+20 pts) ──────────────────────────
    if event.success:
        score += 20
        details.append("INTRUSÃO BEM-SUCEDIDA — acesso ao sistema confirmado")

    # ── 5. Payload malicioso presente (+15 pts) ─────────────────────
    if event.payload_sample and event.payload_sample.strip():
        score += 15
        details.append("Payload malicioso encontrado na requisição")

    # ── 6. ISP/Org suspeito (+10 pts) ───────────────────────────────
    isp_lower = isp.lower()
    if any(kw in isp_lower for kw in _SUSPICIOUS_ISP_KEYWORDS):
        score += 10
        details.append(f"ISP/Org suspeito: {isp}")

    # ── 7. Varredura de portas (+5–10 pts) ──────────────────────────
    n_ports = len(event.ports_tried)
    if n_ports > 20:
        score += 10
        details.append(f"Varredura extensiva: {n_ports} portas distintas")
    elif n_ports > 5:
        score += 5
        details.append(f"Múltiplas portas testadas: {n_ports}")

    # ── 8. Variedade de usernames (+5–10 pts) ───────────────────────
    n_users = len(event.usernames_tried)
    if n_users > 15:
        score += 10
        details.append(f"Lista extensa de usuários testados: {n_users}")
    elif n_users > 5:
        score += 5
        details.append(f"Variedade de usuários testados: {n_users}")

    # ── 9. IP privado (desconto −10 pts) ────────────────────────────
    if is_private_ip(event.ip):
        score = max(0, score - 10)
        details.append("Origem em rede privada (ameaça interna possível)")

    # Cap em 100
    return min(100, score), details


def get_threat_level(score: int) -> ThreatLevel:
    """Converte pontuação numérica em ThreatLevel."""
    if score >= 80:
        return ThreatLevel.CRITICAL
    if score >= 55:
        return ThreatLevel.HIGH
    if score >= 30:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def get_recommendations(
    threat_level: ThreatLevel,
    attack_type:  AttackType,
    success:      bool,
) -> List[str]:
    """
    Gera lista de recomendações de mitigação com base no contexto da análise.
    """
    recs: List[str] = []

    # Intrusão confirmada — ações de resposta imediata
    if success:
        recs += [
            "🚨 AÇÃO IMEDIATA: Revogar todas as sessões ativas deste IP",
            "🚨 Iniciar protocolo de resposta a incidentes (IRP)",
            "🚨 Auditar logs de acesso das últimas 48 horas",
            "🚨 Preservar evidências antes de qualquer limpeza",
        ]

    # Recomendações por nível de ameaça
    if threat_level == ThreatLevel.CRITICAL:
        recs += [
            "Bloquear IP imediatamente no firewall (regra DROP)",
            "Adicionar IP à blacklist do IDS/IPS (Snort / Suricata)",
            "Notificar equipe de segurança e registrar incidente no SIEM",
            "Verificar se outros sistemas foram afetados pelo mesmo IP",
        ]
    elif threat_level == ThreatLevel.HIGH:
        recs += [
            "Bloquear IP no firewall com prioridade alta",
            "Ativar monitoramento intensificado por 72h",
            "Notificar equipe de segurança",
        ]
    elif threat_level == ThreatLevel.MEDIUM:
        recs += [
            "Monitorar IP por 24h antes de decisão de bloqueio definitivo",
            "Ativar autenticação multifator (MFA) para contas afetadas",
        ]

    # Recomendações específicas por tipo de ataque
    _specific: dict = {
        AttackType.BRUTE_FORCE: [
            "Implementar bloqueio automático após 5 tentativas falhas (fail2ban)",
            "Ativar CAPTCHA no endpoint de login",
            "Configurar alertas de múltiplas falhas de autenticação",
        ],
        AttackType.DICTIONARY_ATTACK: [
            "Forçar reset de senhas fracas ou vazadas",
            "Implementar política de senhas: mín. 12 chars + complexidade",
            "Verificar base de senhas contra Have I Been Pwned",
        ],
        AttackType.PORT_SCAN: [
            "Revisar regras de firewall e fechar portas desnecessárias",
            "Garantir que apenas serviços essenciais estejam expostos",
            "Configurar port-knocking ou VPN para serviços sensíveis",
        ],
        AttackType.CREDENTIAL_STUFFING: [
            "Verificar credenciais em haveibeenpwned.com",
            "Forçar troca de senha para usuários afetados",
            "Implementar detecção de login por geolocalização anômala",
        ],
        AttackType.DOS_ATTEMPT: [
            "Ativar rate limiting no endpoint (ex.: 100 req/min por IP)",
            "Considerar proteção anti-DDoS (Cloudflare / AWS Shield)",
            "Configurar limite de conexões no load balancer",
        ],
        AttackType.SQL_INJECTION: [
            "Auditar todo o código: use Prepared Statements / ORM",
            "Ativar WAF (Web Application Firewall) no gateway",
            "Revisar e fortalecer validação de input em todos os endpoints",
            "Executar DAST (Dynamic Application Security Testing)",
        ],
    }
    recs.extend(_specific.get(attack_type, []))

    return recs
