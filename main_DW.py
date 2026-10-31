"""
C.D.K.C.I.A.E
Live Dark Web Threat Intelligence Demo
C:\tor>.\tor.exe
entry, foothold, escalate, struts, patched, leak, dataset, access, crypto

If Tor (or every source) is unreachable the run falls back to the mock
corpus and says so; use --no-fallback to stop instead.
"""

import argparse

from engine.crawlers.tor_session import (
    create_tor_session,
    test_tor_connection
)

from engine.crawlers.darkweb_live_crawler import log_event

from engine.pipeline import run_pipeline

from engine.pipeline_DW import (
    run_darkweb_pipeline
)


def fall_back_to_mock(reason, allowed):

    """
    Reliability fallback: runs the mock-site corpus and labels the
    output as non-live. Returns False when fallback is disabled.
    """

    log_event({"mode": "mock-fallback", "reason": reason,
               "enabled": allowed})

    if not allowed:

        print("\n[ERROR] " + reason)

        print("[ERROR] Fallback disabled (--no-fallback); stopping.")

        return False

    print("\n[FALLBACK] " + reason)

    print(
        "[FALLBACK] Running the mock-site corpus instead. "
        "Results below are NOT live dark web data.\n"
    )

    run_pipeline()

    return True

# ============================================================
# IMPORTING FOR VISUALS ON TERMINAL
# ============================================================

import os

from pyfiglet import Figlet

from colorama import (
    Fore,
    Style,
    init
)

# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--no-fallback",
        action="store_true",
        help="stop instead of running the mock corpus when live "
             "collection is impossible"
    )

    allow_fallback = not parser.parse_args().no_fallback

    # ========================================================
    # TERMINAL SETUP
    # ========================================================

    init(
        autoreset=True
    )

    os.system(

        "cls"

        if os.name == "nt"

        else "clear"
    )

    # ========================================================
    # BANNER
    # ========================================================

    f = Figlet(
        font="slant"
    )

    banner = f.renderText(
        "C.D.K.C.I.A.E"
    )

    print(
        Fore.CYAN
        + "=" * 75
    )

    print(
        Fore.RED
        + banner
    )

    print(
        Fore.YELLOW
        + "        Cross Domain Kill-Chain Impact Assessment Engine"
    )

    print(
        Fore.CYAN
        + "=" * 75
    )

    print(

        Fore.GREEN
        + """
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║                   CYBER THREAT INTELLIGENCE FRAMEWORK                ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """
        + Style.RESET_ALL
    )

    print("=" * 60)

    # ========================================================
    # CREATE TOR SESSION
    # ========================================================

    print(
        "\n[INITIALIZING TOR SESSION]\n"
    )

    session = create_tor_session()

    tor_status = test_tor_connection(
        session
    )

    print(
        tor_status["message"]
    )

    # ========================================================
    # TOR FAILURE
    # ========================================================

    if not tor_status["status"]:

        fall_back_to_mock(
            "Tor connectivity failed: " + tor_status["message"],
            allow_fallback
        )

        return

    # ========================================================
    # KEYWORD INPUT
    # ========================================================

    print(
        "\n[KEYWORD INPUT]\n"
    )

    keyword_input = input(

        "Enter keywords "
        "(comma separated): "
    )

    keywords = [

        keyword.strip()

        for keyword in keyword_input.split(",")

        if keyword.strip()
    ]

    # ========================================================
    # EMPTY KEYWORDS
    # ========================================================

    if not keywords:

        print(

            "\n[ERROR] "
            "No keywords provided."
        )

        return

    # ========================================================
    # START PIPELINE
    # ========================================================

    print(
        "\n[STARTING LIVE CTI PIPELINE]\n"
    )

    output = run_darkweb_pipeline(
        keywords
    )

    if output["status"] == "unreachable":

        fall_back_to_mock(
            "No configured dark web source could be reached.",
            allow_fallback
        )

        return

    if output["status"] == "no_matches":
        return

    # ========================================================
    # FINAL MESSAGE
    # ========================================================

    print("\n")

    print("=" * 60)

    print(
        "LIVE DARK WEB PIPELINE EXECUTION FINISHED"
    )

    print("=" * 60)

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()