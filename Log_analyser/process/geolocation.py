import csv
import ipaddress
import json
import os
import tempfile
import threading
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app_logging import get_logger


logger = get_logger(__name__)
API_URL = "https://ipwho.is/"
LOOKUP_WORKERS = 5
DAILY_REQUEST_LIMIT = 1000
COUNTRY_CACHE_FILE = (
    Path(__file__).resolve().parents[1] / "data" / "ip_country_cache.json"
)
COUNTRY_RANGE_FILE = COUNTRY_CACHE_FILE.with_name("ip_country.csv")
_LOCATION_CACHE = {}
_REQUEST_COUNT_DATE = date.today().isoformat()
_REQUESTS_TODAY = 0
_COUNTRY_TRIES = None
_CACHE_SAVE_LOCK = threading.Lock()
CACHE_REPLACE_ATTEMPTS = 5
CACHE_REPLACE_DELAY = 0.1


class RateLimitError(RuntimeError):
    """Raised when the no-key geolocation service reaches its daily limit."""


def _load_country_cache():
    global _LOCATION_CACHE, _REQUEST_COUNT_DATE, _REQUESTS_TODAY
    if not COUNTRY_CACHE_FILE.is_file():
        return

    try:
        cache = json.loads(COUNTRY_CACHE_FILE.read_text(encoding="utf-8"))
        if not isinstance(cache, dict):
            raise ValueError("Country cache must contain a JSON object")

        locations = cache.get("locations", {})
        if not isinstance(locations, dict):
            raise ValueError("Country cache locations must be a JSON object")
        for ip, location in locations.items():
            address = ipaddress.ip_address(ip)
            if not isinstance(location, dict) or not isinstance(
                location.get("country"), str
            ):
                raise ValueError(f"Invalid cached country record for {ip}")
            _LOCATION_CACHE[str(address)] = {
                "ip": str(address),
                "country": location["country"],
                "country_code": location.get("country_code", ""),
            }

        if cache.get("request_date") == date.today().isoformat():
            requests_today = cache.get("requests_today", 0)
            if not isinstance(requests_today, int) or requests_today < 0:
                raise ValueError("Country cache request count is invalid")
            _REQUEST_COUNT_DATE = cache["request_date"]
            _REQUESTS_TODAY = requests_today
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        logger.exception("Unable to read IP country cache %s", COUNTRY_CACHE_FILE)
        raise


def _save_country_cache():
    global _REQUEST_COUNT_DATE, _REQUESTS_TODAY
    with _CACHE_SAVE_LOCK:
        _REQUEST_COUNT_DATE = date.today().isoformat()
        cache = {
            "request_date": _REQUEST_COUNT_DATE,
            "requests_today": _REQUESTS_TODAY,
            "locations": _LOCATION_CACHE,
        }
        temporary_file = None
        try:
            COUNTRY_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=COUNTRY_CACHE_FILE.parent,
                prefix=COUNTRY_CACHE_FILE.name + ".",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_file = Path(temporary.name)
                json.dump(cache, temporary, ensure_ascii=False, indent=2)

            for attempt in range(CACHE_REPLACE_ATTEMPTS):
                try:
                    os.replace(temporary_file, COUNTRY_CACHE_FILE)
                    temporary_file = None
                    break
                except PermissionError:
                    if attempt + 1 == CACHE_REPLACE_ATTEMPTS:
                        raise
                    time.sleep(CACHE_REPLACE_DELAY)
        except OSError:
            logger.exception("Unable to save IP country cache %s", COUNTRY_CACHE_FILE)
            raise
        finally:
            if temporary_file is not None:
                try:
                    temporary_file.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    logger.exception(
                        "Unable to remove temporary IP country cache %s",
                        temporary_file,
                    )


def _lookup_country(address):
    request = Request(
        API_URL + address,
        headers={
            "Accept": "application/json",
            "User-Agent": "LogAnalyser/1.0",
        },
    )
    try:
        with urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        if error.code == 429:
            logger.error("Tokenless geolocation API daily request limit reached")
            raise RateLimitError(
                "La limite quotidienne de géolocalisation est atteinte."
            ) from None
        logger.warning("Country lookup failed with HTTP status %d", error.code)
        return {"ip": address, "country": "Inconnu", "country_code": ""}
    except (URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as error:
        logger.warning("Country lookup failed (%s)", type(error).__name__)
        return {"ip": address, "country": "Inconnu", "country_code": ""}

    if not isinstance(data, dict):
        logger.warning("Country API returned an invalid response")
        return {"ip": address, "country": "Inconnu", "country_code": ""}
    if data.get("success") is False:
        logger.warning("Country API could not resolve IP %s", address)
        return {"ip": address, "country": "Inconnu", "country_code": ""}

    country = data.get("country")
    if not isinstance(country, str) or not country.strip():
        logger.warning("Country API returned no country for IP %s", address)
        country = "Inconnu"
    return {
        "ip": address,
        "country": country.strip(),
        "country_code": data.get("country_code", ""),
    }


def _load_country_ranges():
    global _COUNTRY_TRIES
    if _COUNTRY_TRIES is not None:
        return _COUNTRY_TRIES

    tries = {4: {}, 6: {}}
    if not COUNTRY_RANGE_FILE.is_file():
        _COUNTRY_TRIES = tries
        return tries

    try:
        with COUNTRY_RANGE_FILE.open(
            mode="r", encoding="utf-8", newline=""
        ) as source:
            reader = csv.DictReader(source)
            if not reader.fieldnames or not {"network", "country"}.issubset(
                reader.fieldnames
            ):
                raise ValueError(
                    "Country CSV must contain network and country columns"
                )

            for line_number, row in enumerate(reader, start=2):
                network_text = (row.get("network") or "").strip()
                country = (row.get("country") or "").strip()
                if not network_text or not country:
                    raise ValueError(
                        f"Empty network or country on CSV line {line_number}"
                    )

                network = ipaddress.ip_network(network_text, strict=False)
                node = tries[network.version]
                network_value = int(network.network_address)
                bit_count = network.max_prefixlen
                for bit_position in range(network.prefixlen):
                    bit = (network_value >> (bit_count - bit_position - 1)) & 1
                    node = node.setdefault(bit, {})
                node["country"] = country
    except (OSError, UnicodeError, csv.Error, ValueError):
        logger.exception("Unable to load local IP country ranges")
        raise

    _COUNTRY_TRIES = tries
    return tries


def _local_country(address):
    node = _load_country_ranges()[address.version]
    country = node.get("country")
    address_value = int(address)
    bit_count = address.max_prefixlen

    for bit_position in range(address.max_prefixlen):
        bit = (address_value >> (bit_count - bit_position - 1)) & 1
        child = node.get(bit)
        if child is None:
            break
        node = child
        if "country" in node:
            country = node["country"]
    return country


def get_location(ip):
    """Return one address country, using the tokenless HTTPS API for public IPs."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Ignoring invalid IP address in authentication logs")
        return None

    normalized_ip = str(address)
    if not address.is_global:
        return {"ip": normalized_ip, "country": "IP privée/réservée"}
    return resolve_locations([normalized_ip])[normalized_ip]


def resolve_locations(ips):
    """Resolve unique IPs, persist results locally, and cap API use per day."""
    global _REQUEST_COUNT_DATE, _REQUESTS_TODAY
    try:
        if not _LOCATION_CACHE:
            _load_country_cache()

        addresses = {}
        for ip in ips:
            address = ipaddress.ip_address(ip)
            normalized_ip = str(address)
            if not address.is_global:
                addresses[normalized_ip] = {
                    "ip": normalized_ip,
                    "country": "IP privée/réservée",
                    "country_code": "",
                }
            else:
                local_country = _local_country(address)
                if local_country:
                    location = {
                        "ip": normalized_ip,
                        "country": local_country,
                        "country_code": "",
                    }
                    addresses[normalized_ip] = location
                    _LOCATION_CACHE[normalized_ip] = location
                elif normalized_ip in _LOCATION_CACHE:
                    addresses[normalized_ip] = _LOCATION_CACHE[normalized_ip]
                else:
                    addresses[normalized_ip] = None

        pending = [ip for ip, location in addresses.items() if location is None]
        if not pending:
            return addresses

        today = date.today().isoformat()
        if _REQUEST_COUNT_DATE != today:
            _REQUEST_COUNT_DATE = today
            _REQUESTS_TODAY = 0

        remaining_quota = max(0, DAILY_REQUEST_LIMIT - _REQUESTS_TODAY)
        selected = pending[:remaining_quota]
        skipped = pending[remaining_quota:]
        for ip in skipped:
            addresses[ip] = {
                "ip": ip,
                "country": "Inconnu",
                "country_code": "",
            }

        if not selected:
            logger.warning(
                "Daily country lookup limit reached; %d IPs remain unresolved",
                len(skipped),
            )
            print(
                "Limite quotidienne de géolocalisation atteinte. "
                "Les IP restantes seront reprises un autre jour."
            )
            return addresses

        _REQUESTS_TODAY += len(selected)
        _save_country_cache()
        print(
            f"Géolocalisation sans jeton : {len(selected)} adresse(s) publique(s) "
            "à résoudre par HTTPS..."
        )
        rate_limited = False
        with ThreadPoolExecutor(max_workers=LOOKUP_WORKERS) as executor:
            futures = {executor.submit(_lookup_country, ip): ip for ip in selected}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    location = future.result()
                except RateLimitError:
                    rate_limited = True
                    location = {
                        "ip": ip,
                        "country": "Inconnu",
                        "country_code": "",
                    }
                    for pending_future in futures:
                        if pending_future is not future:
                            pending_future.cancel()
                except CancelledError:
                    location = {
                        "ip": ip,
                        "country": "Inconnu",
                        "country_code": "",
                    }
                addresses[ip] = location
                if location["country"] != "Inconnu":
                    _LOCATION_CACHE[ip] = location
                _save_country_cache()

        if rate_limited:
            for ip in selected:
                if addresses[ip] is None:
                    addresses[ip] = {
                        "ip": ip,
                        "country": "Inconnu",
                        "country_code": "",
                    }

        if skipped:
            logger.warning(
                "Daily country lookup limit reached; %d IPs remain unresolved",
                len(skipped),
            )
            print(
                f"{len(skipped)} IP(s) dépassent la limite quotidienne ; "
                "elles pourront être résolues un autre jour."
            )
        return addresses
    except Exception:
        logger.exception("Unable to resolve authentication IP countries")
        raise
