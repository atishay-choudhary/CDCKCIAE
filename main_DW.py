"""
C.D.K.C.I.A.E
Live Dark Web Threat Intelligence Demo
C:\tor>.\tor.exe
entry, foothold, escalate, struts, patched, leak, dataset, access, crypto
"""


from engine.crawlers.tor_session import (
    create_tor_session,
    test_tor_connection
)

from engine.pipeline_DW import (
    run_darkweb_pipeline
)

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

        print(

            "\n[ERROR] "
            "Tor connectivity failed."
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

    run_darkweb_pipeline(
        keywords
    )

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