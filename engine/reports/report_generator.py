"""
Threat intelligence report generator.
"""


def generate_report(results, kill_chain, threat_level):

    """
    Generates formatted CLI report.
    """

    print("\n" + "=" * 60)

    print("C.D.K.C.I.A.E THREAT INTELLIGENCE REPORT")

    print("=" * 60)

    print("\n[+] Threat Signals:\n")

    for item in results:

        if item["type"] == "keyword":

            print(
                f"[{item['subtype'].upper()}] "
                f"{item['value']}"
            )

        else:

            print(
                f"[{item['type'].upper()}] "
                f"{item['value']}"
            )

    print("\n[+] Kill Chain Stages:\n")

    for stage in kill_chain:
        print(f" - {stage}")

    print(f"\n[+] Threat Level: {threat_level}")

    print("\n" + "=" * 60)