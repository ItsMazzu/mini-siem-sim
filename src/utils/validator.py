"""
utils/validator.py — Validação e sanitização de entradas.

Funções agnósticas a framework para validar/sanitizar todos os dados
que entram no sistema antes de qualquer processamento.

Princípio de segurança aplicado: "Never trust input" — toda entrada
externa passa por aqui antes de ser usada.
"""

import ipaddress
import re
from typing import Optional


# ─────────────────────────────────────────────
# Validação de IP
# ─────────────────────────────────────────────

def validate_ip(ip: str) -> bool:
    """
    Verifica se a string é um endereço IPv4 ou IPv6 válido.

    Retorna False para strings vazias, None ou malformadas.
    """
    if not ip or not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Retorna True se o IP pertencer a um range privado/reservado.

    Ranges cobertos (RFC 1918 + RFC 5735):
      10.0.0.0/8 · 172.16.0.0/12 · 192.168.0.0/16
      127.0.0.0/8 (loopback) · 169.254.0.0/16 (link-local)
    """
    if not validate_ip(ip):
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_loopback(ip: str) -> bool:
    """Retorna True se o IP for de loopback (127.0.0.0/8 ou ::1)."""
    if not validate_ip(ip):
        return False
    try:
        return ipaddress.ip_address(ip.strip()).is_loopback
    except ValueError:
        return False


# ─────────────────────────────────────────────
# Validação de porta
# ─────────────────────────────────────────────

def validate_port(port) -> Optional[int]:
    """
    Converte e valida um número de porta (0–65535).

    Retorna o inteiro se válido, None caso contrário.
    """
    try:
        p = int(str(port).strip())
        return p if 0 <= p <= 65535 else None
    except (ValueError, TypeError):
        return None


# ─────────────────────────────────────────────
# Sanitização de strings
# ─────────────────────────────────────────────

# Padrão: remove caracteres de controle (exceto tab e newline tratados à parte)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_string(value: str, max_length: int = 500) -> str:
    """
    Remove caracteres de controle e limita o tamanho da string.

    Parâmetros
    ----------
    value      : string a ser sanitizada
    max_length : número máximo de caracteres permitidos (padrão 500)

    Retorna string limpa, nunca None.
    """
    if not isinstance(value, str):
        return ""
    cleaned = _CONTROL_CHARS.sub("", value)
    return cleaned[:max_length]


def sanitize_username(username: str) -> str:
    """
    Sanitiza um nome de usuário: permite apenas letras, números,
    ponto, hífen e underscore (padrão POSIX).
    """
    cleaned = sanitize_string(username, max_length=64)
    return re.sub(r"[^a-zA-Z0-9._\-@]", "", cleaned)
