"""
Tor session management module.

Responsible for:
- SOCKS5 proxy configuration
- Tor-based requests session
- connectivity testing
"""

import requests


# ============================================================
# CREATE TOR SESSION
# ============================================================

def create_tor_session():

    """
    Creates a requests session routed through Tor.
    """

    session = requests.Session()

    session.proxies = {

        "http": "socks5h://127.0.0.1:9050",

        "https": "socks5h://127.0.0.1:9050"
    }

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
# TEST TOR CONNECTIVITY
# ============================================================

def test_tor_connection(session):

    """
    Tests whether traffic is routed through Tor.
    """

    try:

        response = session.get(

            "https://check.torproject.org",

            timeout=30
        )

        if response.status_code == 200:

            if "Congratulations" in response.text:

                return {

                    "status": True,

                    "message": (
                        "Tor connection established successfully."
                    )
                }

        return {

            "status": False,

            "message": (
                "Tor routing detected failure."
            )
        }

    except Exception as e:

        return {

            "status": False,

            "message": str(e)
        }