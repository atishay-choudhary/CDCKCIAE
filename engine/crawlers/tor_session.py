"""
Tor session management module.

Responsible for:
- SOCKS5 proxy configuration
- Tor-based requests session
- connectivity testing (proxy check, then retried routing check)
"""

import socket
import time

import requests


TOR_HOST = "127.0.0.1"
TOR_PORT = 9050

CHECK_URL = "https://check.torproject.org"


# ============================================================
# CREATE TOR SESSION
# ============================================================

def create_tor_session():

    """
    Creates a requests session routed through Tor.
    """

    session = requests.Session()

    proxy = f"socks5h://{TOR_HOST}:{TOR_PORT}"

    session.proxies = {"http": proxy, "https": proxy}

    session.headers.update({

        "User-Agent": (

            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/122.0 Safari/537.36"
        )
    })

    return session


# ============================================================
# TOR PROXY REACHABLE
# ============================================================

def proxy_listening(host=TOR_HOST, port=TOR_PORT, timeout=3):

    """
    True if something accepts connections on the Tor SOCKS port.
    """

    try:

        with socket.create_connection((host, port), timeout=timeout):
            return True

    except OSError:
        return False


# ============================================================
# TEST TOR CONNECTIVITY
# ============================================================

def test_tor_connection(session, attempts=3, wait=5):

    """
    Tests whether traffic is routed through Tor.

    Fails at once, with a specific message, when the SOCKS proxy is
    not running. Otherwise the routing check is retried, because Tor
    needs a while to build circuits right after start-up.
    """

    if not proxy_listening():

        return {

            "status": False,

            "message": (
                f"Tor SOCKS proxy not reachable on {TOR_HOST}:{TOR_PORT}. "
                "Start Tor (e.g. tor.exe) and wait for it to bootstrap."
            )
        }

    message = "Tor routing detected failure."

    for attempt in range(1, attempts + 1):

        try:

            response = session.get(CHECK_URL, timeout=30)

            if (
                response.status_code == 200
                and "Congratulations" in response.text
            ):

                return {

                    "status": True,

                    "message": "Tor connection established successfully."
                }

            message = "Tor routing detected failure."

        except requests.RequestException as e:

            message = f"{type(e).__name__}: {e}"

        if attempt < attempts:

            print(
                f"[TOR] Check {attempt}/{attempts} failed; "
                f"retrying in {wait * attempt}s"
            )

            time.sleep(wait * attempt)

    return {"status": False, "message": message}