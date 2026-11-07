import ipaddress

from app_logging import get_logger


logger = get_logger(__name__)


def get_location(ip):
    """Normalize an IP and return its fallback country label."""
    try:
        address = ipaddress.ip_address(ip)
        country = "Inconnu" if address.is_global else "IP privée/réservée"
        return {"ip": str(address), "country": country}
    except Exception:
        logger.exception("Unable to validate IP address %r", ip)
        raise
