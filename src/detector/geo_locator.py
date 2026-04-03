"""
detector/geo_locator.py — Geolocalização de IPs via ip-api.com.

Usa a API gratuita (sem chave) do ip-api.com:
  http://ip-api.com/json/{ip}?fields=...

Limites da API gratuita: 45 requisições/minuto por IP de origem.
Para produção, use a versão Pro com HTTPS e sem limite.

Segurança:
  - Timeout fixo para evitar bloqueio da thread
  - IPs privados não são enviados à API (retornam GeoInfo local)
  - Erros de rede não propagam exceção — retornam GeoInfo vazia
"""

import requests

from src.models.event import GeoInfo
from src.utils.logger import setup_logger
from src.utils.validator import is_private_ip, validate_ip

logger = setup_logger("geo_locator")

# Campos solicitados à API (minimiza payload de resposta)
_API_FIELDS = "status,message,country,regionName,city,isp,org,lat,lon,timezone,query"
_API_URL    = f"http://ip-api.com/json/{{ip}}?fields={_API_FIELDS}"
_TIMEOUT    = 6  # segundos


def get_geo_info(ip: str) -> GeoInfo:
    """
    Retorna informações de geolocalização para o IP informado.

    Para IPs privados/reservados, retorna um GeoInfo indicando
    'Rede Privada / Local' sem fazer nenhuma requisição externa.

    Em caso de falha de rede ou resposta inválida, retorna um
    GeoInfo com todos os campos em 'Desconhecido'.
    """
    if not validate_ip(ip):
        logger.warning(f"get_geo_info chamado com IP inválido: {ip!r}")
        return GeoInfo()

    if is_private_ip(ip):
        return GeoInfo(
            country="Rede Privada",
            region="Local",
            city="Local",
            isp="Rede Interna",
            org="Rede Interna",
        )

    url = _API_URL.format(ip=ip)
    try:
        resp = requests.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            reason = data.get("message", "resposta não-success")
            logger.warning(f"ip-api.com retornou falha para {ip}: {reason}")
            return GeoInfo()

        return GeoInfo(
            country  = data.get("country",    "Desconhecido"),
            region   = data.get("regionName", "Desconhecido"),
            city     = data.get("city",       "Desconhecido"),
            isp      = data.get("isp",        "Desconhecido"),
            org      = data.get("org",        "Desconhecido"),
            lat      = float(data.get("lat", 0.0)),
            lon      = float(data.get("lon", 0.0)),
            timezone = data.get("timezone",   "Desconhecido"),
        )

    except requests.exceptions.Timeout:
        logger.warning(f"Timeout na geolocalização de {ip} (>{_TIMEOUT}s)")
    except requests.exceptions.ConnectionError:
        logger.warning(f"Sem conectividade ao tentar geolocalizar {ip}")
    except requests.exceptions.HTTPError as e:
        logger.warning(f"HTTP {e.response.status_code} ao geolocalizar {ip}")
    except (ValueError, KeyError) as e:
        logger.error(f"Erro ao parsear resposta da API para {ip}: {e}")

    return GeoInfo()
