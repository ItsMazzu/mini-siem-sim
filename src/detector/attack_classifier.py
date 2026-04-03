"""
detector/attack_classifier.py — Classificação do tipo de ataque.

Analisa os metadados do evento (tentativas, portas, usernames, payload)
e retorna o AttackType mais provável usando uma cascata de regras.

Ordem de prioridade das regras:
  1. SQL Injection  (payload malicioso → detectável independente do volume)
  2. DoS Attempt    (volume extremo de requisições)
  3. Port Scan      (muitas portas distintas)
  4. Credential Stuffing (muitos usernames diferentes)
  5. Dictionary Attack   (alto volume, poucos usernames)
  6. Brute Force         (volume moderado, 1-2 usernames)
  7. Suspicious          (padrão anômalo não classificado)
  8. Normal
"""

from src.models.event import AccessEvent, AttackType

# ─────────────────────────────────────────────
# Padrões de SQL Injection (case-insensitive)
# ─────────────────────────────────────────────
_SQL_PATTERNS = [
    "' OR", "OR '1'='1", "1=1", "' --", "' #",
    "DROP TABLE", "DROP DATABASE",
    "UNION SELECT", "UNION ALL SELECT",
    "INSERT INTO", "UPDATE SET", "DELETE FROM",
    "EXEC(", "EXECUTE(", "EXEC SP_",
    "CAST(", "CONVERT(", "CHAR(", "NCHAR(",
    "XP_CMDSHELL", "SP_EXECUTESQL",
    "INFORMATION_SCHEMA", "SYS.TABLES",
    "/*", "*/", "@@VERSION",
]

# Thresholds de classificação
_THRESHOLD_DOS            = 500   # requisições → DoS
_THRESHOLD_PORT_SCAN      = 10    # portas distintas → Port Scan
_THRESHOLD_CRED_STUFFING_U = 10   # usernames distintos
_THRESHOLD_CRED_STUFFING_A = 20   # tentativas mínimas para Cred. Stuffing
_THRESHOLD_DICT_ATTACK_A  = 50    # tentativas → Dictionary Attack (poucos users)
_THRESHOLD_BRUTE_FORCE_A  = 10    # tentativas → Brute Force (1-2 users)
_THRESHOLD_SUSPICIOUS     = 5     # tentativas → Suspeito


def _has_sql_payload(payload: str) -> bool:
    """Verifica se o payload contém padrões conhecidos de SQL Injection."""
    upper = payload.upper()
    return any(pattern in upper for pattern in _SQL_PATTERNS)


def classify_attack(event: AccessEvent) -> AttackType:
    """
    Classifica o tipo de ataque com base nos metadados do evento.

    Parâmetros
    ----------
    event : AccessEvent com attempts, ports_tried, usernames_tried e payload_sample.

    Retorna
    -------
    AttackType correspondente ao padrão detectado.
    """
    payload    = event.payload_sample or ""
    attempts   = event.attempts
    n_ports    = len(event.ports_tried)
    n_users    = len(event.usernames_tried)

    # 1. SQL Injection — prioridade máxima (payload detectável com poucas tentativas)
    if payload and _has_sql_payload(payload):
        return AttackType.SQL_INJECTION

    # 2. DoS / DDoS — volume extremo de requisições
    if attempts >= _THRESHOLD_DOS:
        return AttackType.DOS_ATTEMPT

    # 3. Port Scan — muitas portas distintas testadas
    if n_ports >= _THRESHOLD_PORT_SCAN:
        return AttackType.PORT_SCAN

    # 4. Credential Stuffing — muitos usernames + volume moderado
    if n_users >= _THRESHOLD_CRED_STUFFING_U and attempts >= _THRESHOLD_CRED_STUFFING_A:
        return AttackType.CREDENTIAL_STUFFING

    # 5. Dictionary Attack — alto volume, poucos ou nenhum username variado
    if attempts >= _THRESHOLD_DICT_ATTACK_A and n_users <= 3:
        return AttackType.DICTIONARY_ATTACK

    # 6. Brute Force — volume moderado, 1-2 usernames
    if attempts >= _THRESHOLD_BRUTE_FORCE_A and n_users <= 2:
        return AttackType.BRUTE_FORCE

    # 7. Suspeito — padrão anômalo, mas não classificável claramente
    if attempts >= _THRESHOLD_SUSPICIOUS:
        return AttackType.SUSPICIOUS

    # 8. Acesso normal
    return AttackType.NORMAL
