"""
PDF Threat Intelligence Report Generator
for the C.D.K.C.I.A.E platform.
"""

# ============================================================
# IMPORTS
# ============================================================

import io

from datetime import datetime

from engine import datastore
from reportlab.platypus import (

    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus.flowables import HRFlowable


# ============================================================
# GENERATE PDF REPORT
# ============================================================

def _factor_lines(factors):
    """FAIR factors as 'Name: LEVEL (n)' lines, one per factor."""

    from xml.sax.saxutils import escape

    levels = {1: "very low", 2: "low", 3: "medium", 4: "high", 5: "very high"}

    return "<br/>".join(
        f"&nbsp;&nbsp;{escape(name.replace('_', ' ').title())}: "
        f"{levels.get(f.get('level'), '?')} ({f.get('level')}/5)"
        for name, f in factors.items()
    )


def generate_pdf_report(report_data, output=None):

    """
    Generates a professional PDF
    threat intelligence report.

    output: optional file-like object (e.g. BytesIO) to write the PDF
    into instead of storing it in generated_file.
    """

    # ========================================================
    # OUTPUT SETUP
    # ========================================================

    buffer = output if output is not None else io.BytesIO()

    report_path = buffer

    # ========================================================
    # DOCUMENT
    # ========================================================

    doc = SimpleDocTemplate(

        report_path,

        pagesize=letter,

        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=30
    )

    styles = getSampleStyleSheet()

    elements = []

    # ========================================================
    # TITLE
    # ========================================================

    title = Paragraph(

        """
        <font size=20>
        <b>
        C.D.K.C.I.A.E Threat Intelligence Report
        </b>
        </font>
        """,

        styles["Title"]
    )

    elements.append(title)

    elements.append(

        Spacer(1, 12)
    )

    generated_time = datetime.now().strftime(

        "%d-%m-%Y %H:%M:%S"
    )

    timestamp = Paragraph(

        f"""
        <font size=10 color='grey'>
        Generated: {generated_time}
        </font>
        """,

        styles["Normal"]
    )

    elements.append(timestamp)

    elements.append(

        Spacer(1, 20)
    )

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Executive Summary</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    executive_summary = report_data.get(

        "executive_summary",

        "No executive summary available."
    )

    elements.append(

        Paragraph(

            str(executive_summary),

            styles["BodyText"]
        )
    )

    elements.append(

        Spacer(1, 20)
    )

    # ========================================================
    # THREAT LEVEL
    # ========================================================

    threat_level = report_data.get(

        "threat_level",

        "UNKNOWN"
    )

    elements.append(

        Paragraph(

            "<b>Threat Severity</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    threat_paragraph = Paragraph(

        f"""
        <font size=14>
        Overall Threat Level:
        <b>{threat_level}</b>
        </font>
        """,

        styles["BodyText"]
    )

    elements.append(threat_paragraph)

    elements.append(

        Spacer(1, 20)
    )

    # ========================================================
    # KILL CHAIN
    # ========================================================

    kill_chain = report_data.get(

        "kill_chain_stages",

        []
    )

    elements.append(

        Paragraph(

            "<b>Kill-Chain Progression</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    if kill_chain:

        kill_chain_text = " → ".join(kill_chain)

    else:

        kill_chain_text = "No significant kill-chain progression identified."

    elements.append(

        Paragraph(

            kill_chain_text,

            styles["BodyText"]
        )
    )

    elements.append(

        Spacer(1, 20)
    )

    # ========================================================
    # THREAT INDICATORS
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Threat Indicators</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    signals = report_data.get(

        "signals",

        []
    )

    table_data = [

        [

            "Category",
            "Indicator"
        ]
    ]

    # ========================================================
    # SIGNAL TABLE ROWS
    # ========================================================

    for signal in signals:

        category = "UNKNOWN"
        value = ""

        if isinstance(signal, dict):

            signal_type = signal.get(

                "type",

                "unknown"
            )

            signal_value = signal.get(

                "value",

                ""
            )

            subtype = signal.get(

                "subtype",

                ""
            )

            if signal_type == "keyword":

                category = subtype.upper()

            else:

                category = signal_type.upper()

            value = signal_value

        elif isinstance(signal, tuple):

            if len(signal) >= 2:

                category = str(signal[0]).upper()

                value = str(signal[1])

        else:

            value = str(signal)

        table_data.append(

            [

                category,
                value
            ]
        )

    signal_table = Table(

        table_data,

        colWidths=[150, 320]
    )

    signal_table.setStyle(

        TableStyle(

            [

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#2F4F4F")
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    1,
                    colors.black
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "BACKGROUND",
                    (0, 1),
                    (-1, -1),
                    colors.whitesmoke
                )
            ]
        )
    )

    elements.append(signal_table)

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # NLP SECTION
    # ========================================================

    elements.append(

        Paragraph(

            "<b>NLP Threat Intelligence</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    important_terms = report_data.get(

        "important_terms",

        []
    )

    for term, score in important_terms[:10]:

        paragraph = Paragraph(

            f"""
            • <b>{term}</b>
            — TF-IDF Score:
            {round(score, 4)}
            """,

            styles["BodyText"]
        )

        elements.append(paragraph)

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # MITRE ATT&CK
    # ========================================================

    elements.append(

        Paragraph(

            "<b>MITRE ATT&amp;CK Mapping</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    mitre_matches = report_data.get(

        "mitre_matches",

        []
    )

    if not mitre_matches:

        elements.append(

            Paragraph(

                "No ATT&amp;CK technique mapping was produced for this run.",

                styles["BodyText"]
            )
        )

    for item in mitre_matches[:10]:

        technique_id = item.get(

            "id",

            "UNKNOWN"
        )

        technique_name = item.get(

            "name",

            ""
        )

        if not technique_name:

            technique_name = item.get(

                "technique",

                "Unknown Technique"
            )

        paragraph = Paragraph(

            f"""
            • <b>[{technique_id}]</b>
            {technique_name}
            """,

            styles["BodyText"]
        )

        elements.append(paragraph)

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # IOC ENRICHMENT SUMMARY
    # ========================================================

    elements.append(

        Paragraph(

            "<b>IOC Enrichment Summary</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    enriched_iocs = report_data.get(

        "enriched_iocs",

        []
    )

    if enriched_iocs:

        enrichment_table = [

            [
                "IOC",
                "Type",
                "Risk",
                "Context"
            ]
        ]

        for item in enriched_iocs:

            ioc_value = item.get(

                "value",

                "UNKNOWN"
            )

            ioc_type = item.get(

                "ioc_type",

                "UNKNOWN"
            ).upper()

            risk = item.get(

                "risk",

                "UNKNOWN"
            ).upper()

            context_parts = []

            # =================================================
            # EMAIL CONTEXT
            # =================================================

            if item.get("domain"):

                context_parts.append(

                    f"Domain: {item['domain']}"
                )

            if item.get("role_account"):

                context_parts.append(

                    "Role Account"
                )

            # =================================================
            # IP CONTEXT
            # =================================================

            if item.get("classification"):

                context_parts.append(

                    item["classification"]
                )

            if item.get("is_private"):

                context_parts.append(

                    "Private IP"
                )

            # =================================================
            # CVE CONTEXT
            # =================================================

            if item.get("severity"):

                context_parts.append(

                    f"Severity: {item['severity']}"
                )

            if item.get("kev"):

                context_parts.append(

                    "Known Exploited Vulnerability"
                )

            context = ", ".join(context_parts)

            enrichment_table.append(

                [
                    ioc_value,
                    ioc_type,
                    risk,
                    context
                ]
            )

        table = Table(

            enrichment_table,

            colWidths=[170, 80, 80, 170]
        )

        table.setStyle(

            TableStyle(

                [

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#4B0082")
                    ),

                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white
                    ),

                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        1,
                        colors.black
                    ),

                    (
                        "FONTNAME",
                        (0, 0),
                        (-1, 0),
                        "Helvetica-Bold"
                    ),

                    (
                        "BACKGROUND",
                        (0, 1),
                        (-1, -1),
                        colors.beige
                    ),

                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        8
                    )
                ]
            )
        )

        elements.append(table)

    else:

        elements.append(

            Paragraph(

                "No IOC enrichment records available.",

                styles["BodyText"]
            )
        )

    elements.append(

        Spacer(1, 25)
    )
        # ========================================================
    # CROSS-DOMAIN IMPACT ANALYSIS
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Cross-Domain Impact Analysis</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    impact_analysis = report_data.get(

        "impact_analysis",

        {}
    )

    if impact_analysis:

        impact_lines = [

            f"""
            <b>Impact Criticality:</b>
            {impact_analysis.get('criticality', 'UNKNOWN')}
            """,

            f"""
            <b>Impact Score:</b>
            {impact_analysis.get('impact_score', 0)}
            """
        ]

        for line in impact_lines:

            elements.append(

                Paragraph(

                    line,

                    styles["BodyText"]
                )
            )

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # PREDICTED ATTACK PATHS (ATT&CK-learned, same as the dashboard)
    # ========================================================

    predicted = report_data.get("predicted_paths") or {}

    multi_stage = [
        p for p in predicted.get("paths", []) if len(p.get("path", [])) > 1
    ]

    if multi_stage:

        elements.append(

            Paragraph(

                "<b>Predicted Attack Paths</b>",

                styles["Heading2"]
            )
        )

        elements.append(

            HRFlowable(
                width="100%"
            )
        )

        elements.append(

            Spacer(1, 10)
        )

        elements.append(

            Paragraph(

                "Most likely routes from the stages observed. Likelihood "
                "is the product of transition probabilities learned from "
                "MITRE ATT&amp;CK intrusion sets "
                f"({str(predicted.get('transition_source', 'learned')).replace('&', '&amp;')}).",

                styles["BodyText"]
            )
        )

        elements.append(

            Spacer(1, 8)
        )

        for item in sorted(
            multi_stage, key=lambda p: -p.get("likelihood", 0)
        )[:8]:

            elements.append(

                Paragraph(

                    f"<b>{' → '.join(item['path'])}</b><br/>"
                    f"Likelihood: {item.get('likelihood', 0):.4f}",

                    styles["BodyText"]
                )
            )

            elements.append(

                Spacer(1, 8)
            )

        critical = predicted.get("centrality", [])[:5]

        if critical:

            elements.append(

                Paragraph(

                    "<b>Stages most paths pass through:</b> "
                    + ", ".join(
                        f"{c['stage']} ({c['betweenness']:.3f})"
                        for c in critical
                    ),

                    styles["BodyText"]
                )
            )

        elements.append(

            Spacer(1, 25)
        )

    # ========================================================
    # PROPAGATION ANALYSIS
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Rule-based Propagation (original engine)</b>" if multi_stage else "<b>Propagation Analysis</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    propagation_summary = report_data.get(

        "propagation_summary",

        []
    )

    if propagation_summary:

        for item in propagation_summary[:8]:

            propagation_text = f"""

            <b>Path:</b>
            {item.get('path', 'UNKNOWN')}<br/>

            <b>Probability:</b>
            {item.get('probability', 0)}<br/>

            <b>Severity:</b>
            {item.get('severity', 'UNKNOWN')}<br/>

            <b>Depth:</b>
            {item.get('depth', 0)}
            """

            elements.append(

                Paragraph(

                    propagation_text,

                    styles["BodyText"]
                )
            )

            elements.append(

                Spacer(1, 12)
            )

    else:

        elements.append(

            Paragraph(

                "No propagation intelligence available.",

                styles["BodyText"]
            )
        )

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # CONSEQUENCE ANALYSIS
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Consequence Analysis</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    consequence_summary = report_data.get(

        "consequence_summary",

        []
    )

    if consequence_summary:

        for item in consequence_summary[:10]:

            consequence_text = f"""

            <b>Stage:</b>
            {item.get('stage', 'UNKNOWN')}<br/>

            <b>Consequence:</b>
            {item.get('consequence', 'UNKNOWN')}<br/>

            <b>Severity:</b>
            {item.get('severity', 'UNKNOWN')}<br/>

            <b>Probability:</b>
            {item.get('probability', 0)}
            """

            elements.append(

                Paragraph(

                    consequence_text,

                    styles["BodyText"]
                )
            )

            elements.append(

                Spacer(1, 12)
            )

    else:

        elements.append(

            Paragraph(

                "No consequence intelligence available.",

                styles["BodyText"]
            )
        )

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # BUSINESS RISK SUMMARY
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Business Risk Summary</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    business_risk = report_data.get(

        "business_risk",

        {}
    )

    business_text = f"""

    <b>Business Risk Score:</b>
    {business_risk.get('score', 0)} / {business_risk.get('max_score', 25)}
    ({business_risk.get('model', 'simplified Open FAIR')})<br/>

    <b>Business Risk Level:</b>
    {business_risk.get('risk_level', 'UNKNOWN')}<br/>
    {_factor_lines(business_risk.get('factors', {}))}
    """

    elements.append(

        Paragraph(

            business_text,

            styles["BodyText"]
        )
    )

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # ENTERPRISE ASSET INTELLIGENCE
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Enterprise Asset Intelligence</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    asset_summary = report_data.get(

        "asset_summary",

        []
    )

    if asset_summary:

        for asset in asset_summary[:10]:

            asset_text = f"""

            <b>Asset:</b>
            {asset.get('asset', 'UNKNOWN')}<br/>

            <b>Business Unit:</b>
            {asset.get('business_unit', 'UNKNOWN')}<br/>

            <b>Criticality:</b>
            {asset.get('criticality', 'UNKNOWN')}<br/>

            <b>Role:</b>
            {asset.get('role', 'UNKNOWN')}
            """

            elements.append(

                Paragraph(

                    asset_text,

                    styles["BodyText"]
                )
            )

            elements.append(

                Spacer(1, 12)
            )

    else:

        elements.append(

            Paragraph(

                "No enterprise assets mapped.",

                styles["BodyText"]
            )
        )

    elements.append(

        Spacer(1, 25)
    )

    # ========================================================
    # ENTERPRISE EXPOSURE SUMMARY
    # ========================================================

    elements.append(

        Paragraph(

            "<b>Enterprise Exposure Summary</b>",

            styles["Heading2"]
        )
    )

    elements.append(

        HRFlowable(
            width="100%"
        )
    )

    elements.append(

        Spacer(1, 10)
    )

    enterprise_exposure = report_data.get(

        "enterprise_exposure",

        {}
    )

    exposure_text = f"""

    <b>Exposure Score:</b>
    {enterprise_exposure.get('exposure_score', 0)} / {enterprise_exposure.get('max_score', 25)}<br/>

    <b>Exposure Level:</b>
    {enterprise_exposure.get('exposure_level', 'UNKNOWN')}<br/>
    {_factor_lines(enterprise_exposure.get('factors', {}))}
    """

    elements.append(

        Paragraph(

            exposure_text,

            styles["BodyText"]
        )
    )

    elements.append(

        Spacer(1, 25)
    )
    
    # ========================================================
    # GRAPH VISUALIZATION
    # ========================================================

    graph_bytes = datastore.latest_file("png", "threat_graph.png")

    if graph_bytes:

        elements.append(

            PageBreak()
        )

        elements.append(

            Paragraph(

                "<b>Threat Relationship Graph</b>",

                styles["Heading2"]
            )
        )

        elements.append(

            HRFlowable(
                width="100%"
            )
        )

        elements.append(

            Spacer(1, 15)
        )

        graph_image = Image(

            io.BytesIO(graph_bytes),

            width=540,
            height=420
        )

        graph_image.hAlign = "CENTER"

        elements.append(graph_image)

    # ========================================================
    # FOOTER
    # ========================================================

    elements.append(

        Spacer(1, 25)
    )

    footer = Paragraph(

        """
        <font size=9 color='grey'>
        Generated by the
        C.D.K.C.I.A.E Threat Intelligence Platform
        </font>
        """,

        styles["Normal"]
    )

    elements.append(footer)

    # ========================================================
    # BUILD PDF
    # ========================================================

    doc.build(elements)

    if output is None:

        datastore.save_file(
            "pdf", "threat_intelligence_report.pdf", buffer.getvalue()
        )

    return "threat_intelligence_report.pdf (database)"