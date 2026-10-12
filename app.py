"""PII Sentinel enterprise Streamlit interface."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json

import fitz
import plotly.graph_objects as go
import streamlit as st

from attack_lab import aggregate_results, all_scenarios, run_scenario
from core.mock_ai import mock_ai_process
from core.frontend_state import (
    activate_upload, aligned_preview_blocks, analysis_cache_key, decision_presentation,
    escape_display, highlighted_placeholders, highlighted_text,
)
from core.pipeline import AnalysisResult, run_secure_analysis
from core.security_gate import evaluate_release
from core.validator import validate_file
from extraction.extractor import extract_document
from extraction.ocr import configure_tesseract
from intelligence import assess_risk, build_recommendations, export_risk_report
from privacy.detector import detect_pii
from privacy.redactor import redact_document, serialize_sanitized
from privacy.verifier import verify_redaction
from reporting.release_receipt import build_release_receipt


PALETTE = {
    "background": "#111827", "sidebar": "#0F172A", "surface": "#1E293B",
    "elevated": "#263449", "primary": "#14B8A6", "primary_hover": "#0D9488",
    "secondary": "#CBD5E1", "muted": "#94A3B8", "border": "#334155",
    "gold": "#D4A85B", "success": "#22C55E", "warning": "#F59E0B",
    "danger": "#EF4444", "text": "#F8FAFC",
}
NAVIGATION = ["Command Center", "Document Analyzer", "Privacy Preview", "Risk Intelligence", "Privacy Attack Lab"]


st.set_page_config(page_title="PII Sentinel", page_icon="🛡", layout="wide", initial_sidebar_state="expanded")
st.markdown(
    f"""
    <style>
    :root {{ --ps-bg:{PALETTE['background']}; --ps-sidebar:{PALETTE['sidebar']};
        --ps-surface:{PALETTE['surface']}; --ps-elevated:{PALETTE['elevated']};
        --ps-primary:{PALETTE['primary']}; --ps-primary-hover:{PALETTE['primary_hover']};
        --ps-text:{PALETTE['text']}; --ps-secondary:{PALETTE['secondary']};
        --ps-muted:{PALETTE['muted']}; --ps-border:{PALETTE['border']};
        --ps-gold:{PALETTE['gold']}; --ps-approved:{PALETTE['success']};
        --ps-blocked:{PALETTE['danger']}; --ps-warning:{PALETTE['warning']}; }}
    .stApp {{ background:var(--ps-bg); color:var(--ps-text); }}
    [data-testid="stSidebar"] {{ background:var(--ps-sidebar); border-right:1px solid var(--ps-border);
        min-width:17rem; max-width:17rem; }}
    [data-testid="stHeader"] {{ background: transparent; }}
    [data-testid="stMainBlockContainer"] {{ max-width:1440px; padding-top:2rem; animation:ps-enter 180ms ease-out; }}
    h1, h2, h3 {{ color:var(--ps-text); letter-spacing:-.025em; }}
    h1 {{ font-size:2rem; }} h2 {{ font-size:1.35rem; }} h3 {{ font-size:1.08rem; }}
    p, label, .stCaption {{ color:var(--ps-secondary); font-size:.92rem; line-height:1.52; }}
    .ps-brand {{ padding: .35rem 0 1rem; }}
    .ps-mark {{ display:inline-flex; width:2.35rem; height:2.35rem; align-items:center;
        justify-content:center; border:1px solid var(--ps-primary); border-radius:.65rem;
        color:var(--ps-primary); font-weight:800; margin-right:.7rem; }}
    .ps-brand-name {{ color:var(--ps-text); font-size:1.16rem; font-weight:750; }}
    .ps-eyebrow {{ color:var(--ps-primary); text-transform:uppercase; letter-spacing:.14em;
        font-size:.8rem; font-weight:750; margin-bottom:.45rem; }}
    .ps-hero {{ background:var(--ps-surface); border:1px solid var(--ps-border); border-radius:.85rem;
        padding:1.35rem 1.55rem; margin-bottom:.8rem; box-shadow:0 10px 24px rgba(0,0,0,.12); }}
    .ps-hero h1 {{ font-size:2rem; margin:.05rem 0 .3rem; }}
    .ps-hero p {{ font-size:1rem; max-width:760px; margin:0; }}
    .ps-card {{ background:var(--ps-elevated); border:1px solid var(--ps-border); border-radius:.75rem;
        padding:.9rem 1rem; min-height:96px; transition:border-color 180ms ease, transform 180ms ease; }}
    .ps-card:hover {{ border-color:#475569; transform:translateY(-1px); }}
    .ps-card-title {{ color:var(--ps-muted); font-size:.75rem; text-transform:uppercase;
        letter-spacing:.08em; font-weight:650; }}
    .ps-card-value {{ color:var(--ps-text); font-size:1.55rem; font-weight:760; margin-top:.25rem; }}
    .ps-callout {{ background:var(--ps-surface); border-left:3px solid var(--ps-gold);
        border-radius:.6rem; padding:.8rem 1rem; color:var(--ps-secondary); margin:.75rem 0; }}
    .ps-status {{ display:inline-block; padding:.25rem .55rem; border-radius:999px;
        background:#123A37; color:var(--ps-approved); font-size:.72rem; font-weight:700; }}
    .ps-future {{ background:{PALETTE['surface']}; border:1px dashed #34445f; border-radius:1rem;
        padding:2rem; text-align:center; margin-top:1rem; }}
    .ps-decision {{ display:flex; flex-direction:column; gap:.35rem; padding:1.15rem 1.25rem;
        margin:.85rem 0; border:1px solid; border-radius:.75rem; background:var(--ps-surface); }}
    .ps-decision strong {{ color:var(--ps-text); font-size:1.02rem; letter-spacing:.01em; }}
    .ps-decision span {{ color:var(--ps-secondary); font-size:.9rem; }}
    .ps-decision.approved {{ border-color:{PALETTE['success']}; box-shadow:inset 4px 0 {PALETTE['success']}; }}
    .ps-decision.blocked {{ border-color:{PALETTE['danger']}; box-shadow:inset 4px 0 {PALETTE['danger']}; }}
    .ps-decision.pending {{ border-color:{PALETTE['warning']}; box-shadow:inset 4px 0 {PALETTE['warning']}; }}
    [data-testid="stMetric"] {{ background:var(--ps-elevated); border:1px solid var(--ps-border);
        border-radius:.75rem; padding:.85rem 1rem; }}
    [data-testid="stFileUploader"] {{ background:var(--ps-surface); border:1px solid var(--ps-border);
        border-radius:.8rem; padding:.25rem; }}
    .stButton > button {{ border-radius:.55rem; min-height:2.55rem; font-weight:650;
        transition:background 180ms ease, border-color 180ms ease, transform 180ms ease; }}
    .stButton > button:hover {{ transform:translateY(-1px); }}
    .stButton > button[kind="primary"] {{ background:var(--ps-primary); color:#06211F; border:0; }}
    .stButton > button[kind="primary"]:hover {{ background:var(--ps-primary-hover); }}
    [data-baseweb="input"], [data-baseweb="select"] > div, textarea {{
        transition:border-color 180ms ease, box-shadow 180ms ease; }}
    [data-baseweb="input"]:focus-within, [data-baseweb="select"] > div:focus-within,
    textarea:focus {{ border-color:var(--ps-primary)!important; box-shadow:0 0 0 1px var(--ps-primary)!important; }}
    [data-baseweb="tag"] {{ background:#294258!important; color:var(--ps-text)!important; }}
    [data-baseweb="tab-list"] button {{ transition:color 180ms ease, border-color 180ms ease; }}
    [data-baseweb="tab-list"] button[aria-selected="true"] {{ color:var(--ps-primary)!important; }}
    div[data-testid="stDataFrame"] {{ border:1px solid var(--ps-border); border-radius:.7rem; overflow:hidden; }}
    [data-testid="stSidebar"] [role="radiogroup"] label {{ padding:.52rem .65rem; margin:.12rem 0;
        border-radius:.5rem; font-size:.93rem; transition:background 180ms ease, color 180ms ease; }}
    [data-testid="stSidebar"] [role="radiogroup"] label:hover {{ background:#17243A; }}
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {{
        background:var(--ps-surface); color:var(--ps-text); box-shadow:inset 3px 0 var(--ps-primary); }}
    [data-testid="stMetricValue"] {{ font-size:1.55rem; }}
    .stTextArea textarea {{ font-family:"Cascadia Mono","Consolas",monospace; font-size:.9rem;
        line-height:1.5; background:#0D1728; color:#E5EDF7; }}
    .ps-preview {{ min-height:390px; max-height:390px; overflow:auto; white-space:pre-wrap;
        overflow-wrap:anywhere; padding:1rem; border:1px solid var(--ps-border); border-radius:.65rem;
        background:#101827; color:#E5EDF7; font:.9rem/1.62 "Cascadia Mono","Consolas",monospace; }}
    .ps-preview mark {{ padding:.08rem .16rem; border-radius:.2rem; color:#07111f; }}
    .ps-sensitive {{ background:#F6C453; }}
    .ps-placeholder {{ background:#39D9B1; }}
    .ps-stages {{ display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:.5rem; margin:.65rem 0 1rem; }}
    .ps-stage {{ padding:.7rem; border:1px solid var(--ps-border); border-radius:.6rem;
        background:var(--ps-surface); color:var(--ps-secondary); min-width:0; }}
    .ps-stage strong {{ display:block; color:var(--ps-text); font-size:.8rem; overflow:hidden; text-overflow:ellipsis; }}
    .ps-stage span {{ color:var(--ps-primary); font-size:.72rem; font-weight:700; }}
    .ps-stepper {{ display:grid; grid-template-columns:repeat(5,1fr); gap:.55rem; }}
    .ps-step {{ background:var(--ps-surface); border-top:2px solid var(--ps-primary); border-radius:.5rem;
        padding:.7rem .8rem; color:var(--ps-secondary); font-size:.82rem; }}
    .ps-step strong {{ display:block; color:var(--ps-text); margin-bottom:.2rem; }}
    .ps-rec {{ background:var(--ps-surface); border:1px solid var(--ps-border); border-radius:.7rem;
        padding:.85rem 1rem; margin:.55rem 0; }}
    .ps-rec strong {{ color:var(--ps-text); }}
    .ps-priority {{ display:inline-block; min-width:4.8rem; margin-right:.55rem; color:var(--ps-gold);
        font-size:.76rem; font-weight:800; text-transform:uppercase; letter-spacing:.06em; }}
    .ps-attack {{ background:var(--ps-surface); border:1px solid var(--ps-border); border-radius:.75rem;
        padding:1rem; min-height:180px; transition:border-color 180ms ease, transform 180ms ease; }}
    .ps-attack:hover {{ border-color:#475569; transform:translateY(-1px); }}
    .ps-attack h3 {{ font-size:1.05rem; margin:.2rem 0 .45rem; }}
    @keyframes ps-enter {{ from {{ opacity:.72; transform:translateY(4px); }} to {{ opacity:1; transform:none; }} }}
    @media (max-width: 1100px) {{ .ps-stages {{ grid-template-columns:repeat(3,1fr); }} }}
    @media (max-width: 900px) {{ .ps-hero h1 {{ font-size:1.7rem; }} .ps-card {{ min-height:88px; }}
        .ps-stepper {{ grid-template-columns:1fr; }} }}
    @media (prefers-reduced-motion:reduce) {{ *, *::before, *::after {{ animation:none!important;
        transition:none!important; scroll-behavior:auto!important; }} }}
    hr {{ border-color:var(--ps-border); }}
    </style>
    """,
    unsafe_allow_html=True,
)


def initialize_state() -> None:
    st.session_state.setdefault("extraction_cache", {})
    st.session_state.setdefault("activity", {})
    st.session_state.setdefault("analysis_cache", {})
    st.session_state.setdefault("active_upload_digest", None)
    st.session_state.setdefault("attack_results", {})
    st.session_state.setdefault("nav", "Command Center")


def section_header(eyebrow: str, title: str, description: str) -> None:
    st.markdown(
        f'<div class="ps-eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p>',
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: int | str) -> None:
    st.markdown(
        f'<div class="ps-card"><div class="ps-card-title">{label}</div>'
        f'<div class="ps-card-value">{value}</div></div>', unsafe_allow_html=True,
    )


def update_activity(key: str, **changes) -> None:
    record = st.session_state.activity.setdefault(key, {
        "filename": "", "format": "", "extraction": "PENDING", "pii": 0,
        "decision": "PENDING", "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "categories": {}, "cache_key": key, "redactions": 0, "residual": 0,
        "verification": "PENDING", "reasons": [],
    })
    record.update(changes)
    record["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    st.session_state.current_record_key = key


def cache_analysis(key: str, analysis: AnalysisResult) -> None:
    """Publish one pipeline result atomically to every frontend view."""

    st.session_state.analysis_cache[key] = analysis
    cache = st.session_state.extraction_cache
    if analysis.document:
        cache[key] = analysis.document
    if analysis.detection:
        cache[f"pii:{key}"] = analysis.detection
    if analysis.redaction and analysis.verification and analysis.decision:
        cache[f"gateway:{key}"] = (
            analysis.redaction, analysis.payload, analysis.verification, analysis.decision,
        )
    document = analysis.document
    detection = analysis.detection
    decision = analysis.decision
    update_activity(
        key,
        filename=analysis.filename,
        format=document.file_type if document else analysis.validation.detected_format or "Unknown",
        extraction=("COMPLETE" if document and document.extraction_complete
                    and not document.extraction_warnings else "PARTIAL" if document else "PENDING"),
        pii=len(detection.findings) if detection else 0,
        categories=dict(Counter(item.entity_type for item in detection.findings)) if detection else {},
        decision=decision.decision if decision else "PENDING",
        redactions=analysis.redaction.redacted_count if analysis.redaction else 0,
        residual=len(analysis.verification.residual_findings) if analysis.verification else 0,
        verification=("PASSED" if analysis.verification and analysis.verification.passed
                      else "FAILED" if analysis.verification else "PENDING"),
        reasons=list(decision.reasons) if decision else [],
    )


def render_decision(analysis: AnalysisResult | None) -> None:
    """Render actual gate evidence; absence of a decision is always pending."""

    state, title = decision_presentation(analysis.decision if analysis else None)
    if state == "PENDING":
        st.markdown('<div class="ps-decision pending"><strong>PENDING — Verification not completed</strong>'
                    '<span>Complete every stage before content can be eligible for AI.</span></div>',
                    unsafe_allow_html=True)
        if analysis and analysis.errors:
            for error in analysis.errors:
                st.error(error)
        st.info("Next action: run Analyze & Secure Document to complete verification.")
        return
    decision = analysis.decision
    if state == "APPROVED":
        state = "approved"
    else:
        state = "blocked"
    st.markdown(f'<div class="ps-decision {state}"><strong>{title}</strong>'
                f'<span>{" ".join(decision.reasons)}</span></div>', unsafe_allow_html=True)
    document = analysis.document
    verification = analysis.verification
    metrics = st.columns(5)
    values = [
        ("Findings", decision.detected_pii_count),
        ("Redacted", decision.redacted_pii_count),
        ("Residual", decision.residual_pii_count),
        ("Extraction", decision.extraction_status),
        ("Verification", decision.verification_status),
    ]
    for column, (label, value) in zip(metrics, values):
        column.metric(label, value)
    if document and document.extraction_warnings:
        with st.expander("Extraction warnings"):
            for warning in document.extraction_warnings:
                st.write(f"- {warning}")
    if verification:
        failed = [name.replace("_", " ").title() for name, passed in verification.checks.items() if not passed]
        if failed:
            st.error("Failed verification checks: " + ", ".join(failed))
    if state == "approved":
        st.success("Next action: inspect the sanitized preview, then send only the approved payload to the local mock AI.")
    else:
        st.warning("Next action: review extraction warnings and failed checks locally; do not release this payload.")


def render_stage_statuses(analysis: AnalysisResult | None) -> None:
    statuses = analysis.stage_statuses if analysis else {
        name: "Pending" for name in
        ("Validation", "Extraction", "Detection", "Redaction", "Verification", "Security gate")
    }
    st.markdown("#### Workflow status")
    stages = [
        f'<div class="ps-stage"><strong>{index}. {stage}</strong><span>{status}</span></div>'
        for index, (stage, status) in enumerate(statuses.items(), start=1)
    ]
    st.markdown(f'<div class="ps-stages">{"".join(stages)}</div>', unsafe_allow_html=True)


def render_sidebar() -> None:
    with st.sidebar:
        st.markdown(
            '<div class="ps-brand"><span class="ps-mark">PS</span>'
            '<span class="ps-brand-name">PII Sentinel</span></div>', unsafe_allow_html=True,
        )
        st.caption("KNOW WHAT AI SEES")
        st.radio("Workspace", NAVIGATION, key="nav", label_visibility="collapsed")
        st.divider()
        current = st.session_state.activity.get(st.session_state.get("current_record_key", ""))
        st.caption("CURRENT PROCESSING STATUS")
        if current:
            st.write(current["filename"])
            status = current["decision"] if current["decision"] != "PENDING" else current["extraction"]
            st.markdown(f'<span class="ps-status">{status}</span>', unsafe_allow_html=True)
        else:
            st.write("No active document")
        ocr = configure_tesseract()
        st.divider()
        st.markdown('<span class="ps-status">LOCAL PROCESSING</span>', unsafe_allow_html=True)
        st.caption("Files and detection remain on this machine.")
        st.caption(f"OCR: {'Ready' if ocr.available else 'Unavailable'}")
        st.warning("Prototype / Demo", icon=None)
        st.caption("Optiv Case Study 2 · Independent competition project · Not an Optiv certification")


def render_command_center() -> None:
    st.markdown(
        '<div class="ps-hero"><div class="ps-eyebrow">Privacy operations</div>'
        '<h1>Your AI Privacy Command Center</h1>'
        '<p>Detect sensitive data. Understand exposure. Control what reaches AI.</p></div>',
        unsafe_allow_html=True,
    )
    cta, reassurance = st.columns([1, 2.35], vertical_alignment="center")
    if cta.button("Analyze Document", type="primary", use_container_width=True):
        st.session_state.nav = "Document Analyzer"
        st.rerun()
    reassurance.caption("Local-first processing · fail-closed release control · no external AI upload")
    records = list(st.session_state.activity.values())
    total_pii = sum(record["pii"] for record in records)
    approved = sum(record["decision"] == "APPROVED" for record in records)
    blocked = sum(record["decision"] == "BLOCKED" for record in records)
    pending = sum(record["decision"] == "PENDING" for record in records)
    columns = st.columns(4)
    for column, label, value in zip(columns,
        ["Documents analyzed", "Total PII findings", "Verified releases", "Blocked documents"],
        [len(records), total_pii, approved, blocked]):
        with column:
            metric_card(label, value)

    if records:
        latest = max(records, key=lambda item: item["timestamp"])
        state = latest["decision"]
        css_state = "approved" if state == "APPROVED" else "blocked" if state == "BLOCKED" else "pending"
        description = " ".join(latest.get("reasons", [])) or "Verification has not completed."
        safe_filename = escape_display(latest["filename"])
        safe_description = escape_display(description)
        st.markdown(
            f'<div class="ps-decision {css_state}"><strong>Latest security decision · {state}</strong>'
            f'<span>{safe_filename} · {latest["extraction"]} extraction · '
            f'{latest["pii"]} findings · {latest.get("verification", "PENDING")} verification</span>'
            f'<span>{safe_description}</span></div>', unsafe_allow_html=True,
        )
    else:
        st.markdown('<div class="ps-decision pending"><strong>Current document status · No document selected</strong>'
                    '<span>Analyze a supported document to establish a security decision.</span></div>',
                    unsafe_allow_html=True)

    st.markdown(
        '<div class="ps-callout"><strong>Security principle:</strong> extraction is evidence collection, '
        'not approval. A document reaches the local mock AI only after redaction, independent verification, '
        'and an APPROVED gate decision.</div>', unsafe_allow_html=True,
    )
    left, right = st.columns([1.5, 1], gap="large")
    with left:
        st.subheader("Recent document activity")
        if records:
            recent = sorted(records, key=lambda item: item["timestamp"], reverse=True)[:8]
            st.dataframe([{
                "Filename": item["filename"], "Format": item["format"],
                "Extraction": item["extraction"], "PII findings": item["pii"],
                "Gate": item["decision"], "Updated (UTC)": item["timestamp"],
            } for item in recent], use_container_width=True, hide_index=True)
        else:
            st.info("No documents have been processed in this session.")
    with right:
        st.subheader("PII distribution")
        distribution = Counter()
        for record in records:
            distribution.update(record["categories"])
        if distribution:
            figure = go.Figure(go.Pie(
                labels=list(distribution), values=list(distribution.values()), hole=.66,
                marker={"colors": [PALETTE["primary"], PALETTE["gold"], PALETTE["danger"],
                                     PALETTE["success"], "#8B5CF6", "#38BDF8", "#FB7185", "#A3E635"]},
                textinfo="label+percent",
            ))
            figure.update_layout(
                height=330, margin=dict(l=10, r=10, t=10, b=10), showlegend=False,
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": PALETTE["text"]},
            )
            st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("PII categories will appear after detection runs.")
        st.subheader("Security status")
        a, b, c = st.columns(3)
        a.metric("Approved", approved)
        b.metric("Blocked", blocked)
        c.metric("Pending", pending)

    st.subheader("Protection workflow")
    workflow = []
    for title, copy in [
        ("01 · Validate", "Confirm true file type and safe container structure."),
        ("02 · Extract", "Recover native and image-based content locally."),
        ("03 · Detect", "Find source-traceable PII with hybrid recognition."),
        ("04 · Redact", "Replace exact spans with deterministic placeholders."),
        ("05 · Verify", "Rescan the payload and enforce the release gate."),
    ]:
        workflow.append(f'<div class="ps-step"><strong>{title}</strong>{copy}</div>')
    st.markdown(f'<div class="ps-stepper">{"".join(workflow)}</div>', unsafe_allow_html=True)


def render_document_analyzer() -> None:
    section_header("Document analyzer", "Inspect before AI sees it",
                   "Validate, extract, detect, redact, and verify a document through one local workflow.")
    uploaded = st.file_uploader("Upload PDF, DOCX, or PPTX", type=["pdf", "docx", "pptx"],
                                help="Maximum 20 MB. Uploaded bytes are held only in this local session.", key="analyzer_upload")
    if uploaded is None:
        st.session_state.active_upload_digest = None
        st.info("Choose a supported document to begin. Nothing is uploaded to an external service.")
        return

    data = uploaded.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    activate_upload(st.session_state, digest)
    validation = validate_file(data, uploaded.name)
    a, b, c = st.columns(3)
    a.metric("File", uploaded.name)
    b.metric("Detected format", validation.detected_format or "Unknown")
    c.metric("Size", f"{validation.file_size / 1024:,.1f} KB")
    if not validation.is_valid:
        st.error(f"Validation blocked this file: {validation.reason}")
        return
    st.success(validation.reason)

    cache = st.session_state.extraction_cache
    mode = st.segmented_control("Processing scope", ["Full document", "Selected Pages Demo"],
                                default="Full document", key="processing_scope")
    selected_pages = None
    if mode == "Selected Pages Demo":
        if validation.detected_format != "PDF":
            st.warning("Selected Pages Demo is available for PDF documents only.")
        else:
            with fitz.open(stream=data, filetype="pdf") as pdf:
                page_count = pdf.page_count
            start_col, end_col = st.columns(2)
            start = start_col.number_input("Start page", 1, page_count, 1)
            end = end_col.number_input("End page", 1, page_count, min(3, page_count))
            if start <= end:
                selected_pages = list(range(int(start), int(end) + 1))
            else:
                st.error("Start page must not be after end page.")
            st.warning("Demo output is always PARTIAL and can never authorize full-document release.")

    can_run = mode == "Full document" or selected_pages is not None
    cache_key = analysis_cache_key(data, selected_pages)
    st.subheader("Secure analysis")
    st.caption("One controlled action runs the complete local privacy sequence and stops safely on stage failure.")
    if st.button("Analyze & Secure Document", type="primary", disabled=not can_run,
                 use_container_width=True):
        cached_analysis = st.session_state.analysis_cache.get(cache_key)
        if cached_analysis:
            st.info("Reused the completed result for this exact document and processing scope. No OCR or detection was repeated.")
            cache_analysis(cache_key, cached_analysis)
        else:
            progress = st.progress(0, text="Ready to validate")
            stage_status = st.empty()

            def update_stage(done: int, total: int, message: str) -> None:
                progress.progress(done / total, text=message)
                stage_status.caption(f"Stage {min(done + 1, total)} of {total} · {message}")

            def update_extraction(done: int, total: int) -> None:
                stage_status.caption(f"Extraction · source unit {done} of {total}")

            with st.spinner("Processing locally. OCR may take several minutes."):
                analysis = run_secure_analysis(
                    data, uploaded.name, ocr_status=configure_tesseract(),
                    selected_pages=selected_pages, progress_callback=update_stage,
                    extraction_progress=update_extraction,
                )
            cache_analysis(cache_key, analysis)
            if analysis.completed:
                progress.progress(1.0, text="All six stages completed")
            else:
                progress.empty()

    analysis = st.session_state.analysis_cache.get(cache_key)
    render_stage_statuses(analysis)
    render_decision(analysis)

    with st.expander("Advanced Controls · individual stages"):
        st.caption("Debug controls expose intermediate evidence. They do not bypass verification or the gate.")
        if st.button("1 · Run extraction", disabled=not can_run):
            progress = st.progress(0, text="Preparing local extraction")

            def update_progress(done: int, total: int) -> None:
                progress.progress(done / total, text=f"Processing source unit {done} of {total}")

            with st.spinner("Extracting locally. OCR may take several minutes."):
                cache[cache_key] = extract_document(
                    data, uploaded.name, configure_tesseract(), selected_pages, update_progress,
                )
            progress.progress(1.0, text="Extraction complete")
            result = cache[cache_key]
            update_activity(cache_key, filename=uploaded.name, format=result.file_type,
                            extraction="COMPLETE" if result.extraction_complete else "PARTIAL")

    result = cache.get(cache_key)
    if not result:
        return
    native = sum(block.extraction_status == "native" for block in result.blocks)
    ocr = sum(block.extraction_status == "ocr" for block in result.blocks)
    st.subheader("Extraction coverage")
    x, y, z = st.columns(3)
    x.metric("Extracted blocks", len(result.blocks)); y.metric("Native", native); z.metric("OCR", ocr)
    if result.extraction_complete:
        st.success("COMPLETE · All discovered content was processed without extraction warnings.")
    else:
        st.warning("PARTIAL · Extraction requires review and cannot pass the security gate.")
        for warning in result.extraction_warnings:
            st.warning(warning)

    detection_key = f"pii:{cache_key}"
    with st.expander("Advanced · detection and gate controls"):
        if st.button("2 · Detect PII", disabled=not result.blocks):
            with st.spinner("Running Presidio, spaCy, and local recognizers"):
                cache[detection_key] = detect_pii(result)
            detection = cache[detection_key]
            counts = Counter(item.entity_type for item in detection.findings)
            update_activity(cache_key, pii=len(detection.findings), categories=dict(counts))
    detection = cache.get(detection_key)
    if not detection:
        return

    st.subheader("Detected sensitive data")
    st.caption("Recognition scores are model signals, not measured accuracy probabilities.")
    if detection.findings:
        categories = sorted({item.entity_type for item in detection.findings})
        methods = sorted({item.detection_method for item in detection.findings})
        sources = sorted({item.source_page_or_slide for item in detection.findings if item.source_page_or_slide is not None})
        f1, f2, f3 = st.columns(3)
        category_filter = f1.multiselect("Category", categories, default=categories)
        method_filter = f2.multiselect("Method", methods, default=methods)
        source_filter = f3.multiselect("Page / slide", sources, default=sources)
        filtered = [item for item in detection.findings if item.entity_type in category_filter
                    and item.detection_method in method_filter
                    and (item.source_page_or_slide is None or item.source_page_or_slide in source_filter)]
        st.dataframe([{
            "Entity": item.entity_type, "Masked preview": item.masked_preview,
            "Method": item.detection_method, "Score": item.confidence_score,
            "Page/slide": item.source_page_or_slide, "Source": item.source_location,
        } for item in filtered], use_container_width=True, hide_index=True)
    else:
        st.warning("No PII was detected. This does not prove that the document is PII-free.")

    gateway_key = f"gateway:{cache_key}"
    with st.expander("Advanced · redaction and verification"):
        if st.button("3–6 · Redact, verify, and evaluate gate", type="secondary"):
            redaction = redact_document(result, detection.findings)
            if not redaction.succeeded:
                st.error("Redaction failed: " + " ".join(redaction.errors))
            else:
                payload = serialize_sanitized(redaction)
                verification = verify_redaction(result, detection, redaction, payload,
                                                  selected_pages_demo=mode == "Selected Pages Demo")
                decision = evaluate_release(
                    validation_succeeded=validation.is_valid, document=result, detection=detection,
                    redaction=redaction, verification=verification, payload=payload,
                    selected_pages_demo=mode == "Selected Pages Demo",
                )
                cache[gateway_key] = (redaction, payload, verification, decision)
                update_activity(cache_key, decision=decision.decision)

    gateway = cache.get(gateway_key)
    if gateway:
        redaction, payload, verification, decision = gateway
        status_fn = st.success if decision.decision == "APPROVED" else st.error
        status_fn(f"Security gate: {decision.decision}")
        for reason in decision.reasons:
            st.write(f"- {reason}")
        st.info("Open Privacy Preview for the before/after view and release receipt.")


def render_privacy_preview() -> None:
    section_header("Privacy preview", "See exactly what changes",
                   "Compare trusted local source text with the sanitized payload and inspect the gate evidence.")
    key = st.session_state.get("current_record_key")
    record = st.session_state.activity.get(key or "")
    if not record:
        st.info("Analyze a document first to populate the privacy preview.")
        return
    cache = st.session_state.extraction_cache
    result = cache.get(key)
    detection = cache.get(f"pii:{key}")
    gateway = cache.get(f"gateway:{key}")
    analysis = st.session_state.analysis_cache.get(key)
    st.caption(f"CURRENT DOCUMENT · {record['filename']} · {record['format']}")
    a, b, c = st.columns(3)
    a.metric("Extraction", record["extraction"]); b.metric("PII findings", record["pii"]); c.metric("Gate", record["decision"])
    if not result:
        st.warning("The cached extraction is no longer available.")
        return
    if not gateway:
        render_decision(analysis)
        st.warning("Sanitized preview pending. Redaction and verification have not completed.")
        with st.expander("Original document content · trusted local inspection"):
            st.text_area("Original", result.text[:12000], height=360, disabled=True,
                         label_visibility="collapsed")
        return
    redaction, payload, verification, decision = gateway
    if not analysis:
        analysis = AnalysisResult(record["filename"], validate_file(b"", record["filename"]),
                                  document=result, detection=detection, redaction=redaction,
                                  payload=payload, verification=verification, decision=decision)
    boundaries: list[tuple[str, int]] = []
    for block in result.blocks:
        boundary = (("Page", block.metadata.get("page")) if isinstance(block.metadata.get("page"), int)
                    else ("Slide", block.metadata.get("slide")) if isinstance(block.metadata.get("slide"), int)
                    else None)
        if boundary and boundary not in boundaries:
            boundaries.append(boundary)
    selected_boundary = None
    if boundaries:
        selected_boundary = st.selectbox(
            "Page / slide", boundaries, format_func=lambda item: f"{item[0]} {item[1]}",
            help="Navigate document structure before choosing the aligned content block.",
        )
    visible_blocks = [block for block in result.blocks if not selected_boundary or (
        block.metadata.get("page") == selected_boundary[1] if selected_boundary[0] == "Page"
        else block.metadata.get("slide") == selected_boundary[1]
    )]
    options = [block.block_id for block in visible_blocks]
    labels = {
        block.block_id: f"{block.source_location} · {block.block_type} · {block.block_id}"
        for block in result.blocks
    }
    selected_id = st.selectbox(
        "Aligned source block", options,
        format_func=lambda block_id: labels[block_id],
        help="Both panels always show the same extracted page, slide, or logical block.",
    )
    original_block, sanitized_block = aligned_preview_blocks(result, redaction, selected_id)
    original_spans = [
        (finding.start_offset, finding.end_offset) for finding in (detection.findings if detection else [])
        if finding.block_id == selected_id
    ]
    original_markup = highlighted_text(original_block.text, original_spans, "ps-sensitive")
    sanitized_markup = highlighted_placeholders(sanitized_block.text)
    left, right = st.columns(2, gap="large")
    with left:
        with st.container(border=True):
            st.markdown("### Original Document — Trusted Local View")
            st.warning("Contains unredacted sensitive data. Never copy this view to an AI system.")
            st.markdown(f'<div class="ps-preview">{original_markup}</div>', unsafe_allow_html=True)
    with right:
        with st.container(border=True):
            st.markdown("### What AI Sees — Sanitized Content")
            if decision.decision == "APPROVED":
                st.success("AUTHORIZED · This verified sanitized payload is eligible for the local mock AI.")
            else:
                st.error("NOT AUTHORIZED FOR AI PROCESSING · Trusted local inspection only.")
            st.markdown(f'<div class="ps-preview">{sanitized_markup}</div>', unsafe_allow_html=True)

    st.subheader("Verification evidence")
    render_decision(analysis)

    with st.expander("Inspect complete serialized payload"):
        st.text_area("Complete candidate payload", payload[:24000], height=360, disabled=True,
                     help="Blocked payloads remain local and cannot be sent to the mock endpoint.")
    st.subheader("Privacy Release Receipt")
    receipt = build_release_receipt(decision)
    st.dataframe([{"Control": key, "Result": value} for key, value in receipt.items()],
                 use_container_width=True, hide_index=True)
    st.download_button(
        "Export safe receipt (JSON)",
        data=json.dumps(receipt, indent=2),
        file_name=f"pii-sentinel-receipt-{decision.document_id}.json",
        mime="application/json",
        help="Receipt exports contain statuses, counts, hashes, and reasons—never source text or raw PII.",
    )
    if decision.approved_payload:
        if st.button("Send Verified Content to Mock AI", type="primary"):
            response = mock_ai_process(decision.approved_payload, decision)
            st.success(response["message"])
    else:
        st.button("Send to local mock AI", disabled=True, help="The security gate blocked this payload.")


def render_risk_intelligence() -> None:
    section_header(
        "Risk intelligence", "Explain the original exposure",
        "Assess potential exposure before redaction without changing verification or release authority.",
    )
    key = st.session_state.get("current_record_key")
    if not key:
        st.info("Analyze a document to calculate an evidence-based potential exposure rating.")
        return
    cache = st.session_state.extraction_cache
    document = cache.get(key)
    detection = cache.get(f"pii:{key}")
    gateway = cache.get(f"gateway:{key}")
    if not document or not detection:
        st.info("Extraction and detection must complete before risk intelligence is available.")
        return
    redaction = verification = decision = None
    if gateway:
        redaction, _payload, verification, decision = gateway
    assessment = assess_risk(document, detection)
    recommendations = build_recommendations(assessment, document, verification, decision)
    if assessment.status != "AVAILABLE":
        st.error("Risk assessment unavailable.")
        for warning in assessment.assessment_warnings:
            st.warning(warning)
        return

    score = assessment.score or 0
    top_left, top_right = st.columns([1, 1.45], gap="large")
    with top_left:
        gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=score,
            number={"suffix": "/100", "font": {"color": PALETTE["text"], "size": 36}},
            title={"text": "Potential original-data exposure", "font": {"color": PALETTE["muted"]}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": PALETTE["muted"]},
                "bar": {"color": PALETTE["primary"]}, "bgcolor": PALETTE["elevated"],
                "steps": [
                    {"range": [0, 30], "color": "#163B42"},
                    {"range": [30, 50], "color": "#4A4025"},
                    {"range": [50, 75], "color": "#4B3025"},
                    {"range": [75, 100], "color": "#4B252D"},
                ],
            },
        ))
        gauge.update_layout(height=300, margin=dict(l=25, r=25, t=55, b=15),
                            paper_bgcolor="rgba(0,0,0,0)", font={"color": PALETTE["text"]})
        st.plotly_chart(gauge, use_container_width=True, config={"displayModeBar": False})
        st.markdown(f"### {assessment.risk_level}")
        st.caption("Original exposure estimate · not a breach probability and not release authorization")
    with top_right:
        st.subheader("How the score was calculated")
        st.info(assessment.calculation_explanation)
        m1, m2, m3 = st.columns(3)
        m1.metric("Maximum sensitivity", f"{assessment.maximum_sensitivity_weight}/5")
        m2.metric("Distinct PII", assessment.distinct_pii_count)
        m3.metric("Record linkage", "Established" if assessment.linkage_indicator else "Not established")
        st.caption("Weights are project assumptions, not official Cadence policy ratings.")

    st.subheader("Three independent security signals")
    controls = st.columns(3)
    controls[0].metric("Original exposure", f"{score}/100 · {assessment.risk_level}")
    controls[1].metric("Sanitized verification", decision.verification_status if decision else "PENDING")
    controls[2].metric("Release decision", decision.decision if decision else "PENDING")
    st.caption("Original exposure never overrides verification or the fail-closed release gate.")

    chart_col, category_col = st.columns([1.4, 1], gap="large")
    with chart_col:
        st.subheader("Detected category distribution")
        if assessment.category_counts:
            category_chart = go.Figure(go.Bar(
                x=list(assessment.category_counts.values()),
                y=list(assessment.category_counts), orientation="h",
                marker_color=PALETTE["primary"], text=list(assessment.category_counts.values()),
            ))
            category_chart.update_layout(
                height=330, margin=dict(l=10, r=20, t=10, b=25),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": PALETTE["text"]}, xaxis_title="Findings",
                yaxis={"autorange": "reversed"},
            )
            st.plotly_chart(category_chart, use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No PII detected — detection does not guarantee absence.")
    with category_col:
        st.subheader("Top contributors")
        if assessment.top_contributing_categories:
            for category in assessment.top_contributing_categories:
                st.markdown(
                    f'<div class="ps-card"><div class="ps-card-title">{category}</div>'
                    f'<div class="ps-card-value">{assessment.category_counts[category]}</div></div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No contributing categories were identified.")

    st.subheader("Prioritized security recommendations")
    if recommendations:
        for item in recommendations:
            st.markdown(
                f'<div class="ps-rec"><span class="ps-priority">{item.priority}</span>'
                f'<strong>{item.title}</strong><p>{item.action}</p><small>{item.rationale}</small></div>',
                unsafe_allow_html=True,
            )
    else:
        st.info("No condition-specific recommendations are available.")
    with st.expander("Assessment assumptions and warnings"):
        for warning in assessment.assessment_warnings:
            st.write(f"- {warning}")

    report = export_risk_report(
        assessment, recommendations,
        extraction_status=("COMPLETE" if document.extraction_complete and not document.extraction_warnings else "PARTIAL"),
        verification_status=decision.verification_status if decision else "PENDING",
        release_decision=decision.decision if decision else "PENDING",
    )
    st.download_button(
        "Export aggregate risk report (JSON)", json.dumps(report, indent=2),
        file_name=f"pii-sentinel-risk-{document.document_id}.json", mime="application/json",
        help="Contains aggregate counts and control states only—never source text or raw PII.",
    )


def render_attack_lab() -> None:
    section_header(
        "Adversarial assurance", "Privacy Attack Lab",
        "Run synthetic evasion, OCR, cross-block, precision, and extraction-failure tests through the real gateway.",
    )
    st.warning(
        "Laboratory fixtures are entirely synthetic. A containment pass is not the same as detection success, "
        "and six scenarios do not establish exhaustive security assurance."
    )
    scenarios = all_scenarios()
    for row_start in range(0, len(scenarios), 3):
        columns = st.columns(3, gap="medium")
        for column, scenario in zip(columns, scenarios[row_start:row_start + 3]):
            with column:
                st.markdown(
                    f'<div class="ps-attack"><div class="ps-eyebrow">{scenario.difficulty} · '
                    f'{scenario.document_format}</div><h3>{scenario.name}</h3><p>{scenario.objective}</p></div>',
                    unsafe_allow_html=True,
                )
                if st.button(f"Run {scenario.name}", key=f"run-{scenario.scenario_id}",
                             use_container_width=True):
                    _execute_attack_scenarios([scenario.scenario_id])

    selected = st.selectbox(
        "Selected scenario", [scenario.scenario_id for scenario in scenarios],
        format_func=lambda value: next(item.name for item in scenarios if item.scenario_id == value),
    )
    run_selected, run_all = st.columns(2)
    if run_selected.button("Run Selected Scenario", type="primary", use_container_width=True):
        _execute_attack_scenarios([selected])
    if run_all.button("Run All Six Scenarios", use_container_width=True):
        _execute_attack_scenarios([scenario.scenario_id for scenario in scenarios])

    results = list(st.session_state.attack_results.values())
    if not results:
        st.info("No attack scenarios have been executed in this session. No outcomes are assumed.")
        return
    summary = aggregate_results(results)
    st.subheader("Measured laboratory results")
    metric_columns = st.columns(5)
    for column, label, value in zip(metric_columns,
        ["Executed", "Detection successes", "Containment passes", "Containment failures", "Inconclusive"],
        [summary.scenarios_executed, summary.detection_successes, summary.containment_passes,
         summary.containment_failures, summary.inconclusive_tests]):
        column.metric(label, value)
    st.dataframe([{
        "Scenario": result.scenario_name,
        "Detection": result.detection_outcome,
        "Containment": result.containment_outcome,
        "Usability": result.usability_outcome,
        "Release": result.release_decision,
        "Runtime (s)": round(result.runtime_seconds, 2),
    } for result in results], use_container_width=True, hide_index=True)

    for result in results:
        icon = "🚨" if result.containment_outcome == "FAIL" else "✓" if result.containment_outcome == "PASS" else "•"
        with st.expander(f"{icon} {result.scenario_name} · containment {result.containment_outcome}"):
            a, b, c, d = st.columns(4)
            a.metric("Expected entities", result.expected_entity_count)
            b.metric("Detected ground truth", result.detected_ground_truth_count)
            c.metric("Ground truth redacted", result.redacted_ground_truth_count)
            d.metric("False positives", result.false_positive_count)
            st.write(f"**Extraction:** {result.extraction_status}  |  **Gate:** {result.release_decision}  |  "
                     f"**Runtime:** {result.runtime_seconds:.2f}s")
            if result.ocr_average_confidence is not None:
                st.write(f"**OCR mean word confidence:** {result.ocr_average_confidence:.2f} "
                         "(OCR engine signal, not detection accuracy)")
            if result.missed_entity_types:
                st.warning("Missed ground-truth categories: " + ", ".join(result.missed_entity_types))
            if result.approved_payload_leakage:
                st.error("CRITICAL: independently known synthetic PII reached an approved mock-AI payload.")
            if result.error_category:
                st.write(f"**Error category:** {result.error_category}")
            st.markdown("**Verification and gate evidence**")
            for reason in result.verification_reasons:
                st.write(f"- {reason}")
            st.markdown("**Lessons and safe mitigations**")
            for lesson in result.lessons:
                st.write(f"- {lesson}")
            for mitigation in result.mitigations:
                st.write(f"- {mitigation}")


def _execute_attack_scenarios(scenario_ids: list[str]) -> None:
    status = st.status("Starting local adversarial execution", expanded=True)
    for scenario_id in scenario_ids:
        scenario = next(item for item in all_scenarios() if item.scenario_id == scenario_id)
        if scenario_id in st.session_state.attack_results:
            status.write(f"{scenario.name}: reused genuine completed session result")
            continue
        progress = st.progress(0, text=f"{scenario.name} · preparing")

        def update_stage(done: int, total: int, message: str, name: str = scenario.name) -> None:
            progress.progress(done / total, text=f"{name} · {message}")

        result = run_scenario(scenario_id, update_stage)
        st.session_state.attack_results[scenario_id] = result
        progress.progress(1.0, text=f"{scenario.name} · completed in {result.runtime_seconds:.2f}s")
        status.write(f"{scenario.name}: {result.containment_outcome}")
    status.update(label="Attack Lab execution complete", state="complete", expanded=False)


def render_future_module(name: str, description: str, capabilities: list[str]) -> None:
    section_header("Future module", name, description)
    st.markdown(
        '<div class="ps-future"><div class="ps-eyebrow">Unavailable in this phase</div>'
        '<h2>Planned, not simulated</h2><p>No scores, recommendations, attacks, or results are generated here.</p></div>',
        unsafe_allow_html=True,
    )
    st.subheader("Planned capabilities")
    columns = st.columns(len(capabilities))
    for column, capability in zip(columns, capabilities):
        with column:
            st.markdown(f'<div class="ps-card"><div class="ps-card-title">Roadmap</div><p>{capability}</p></div>',
                        unsafe_allow_html=True)
    st.button(f"{name} unavailable", disabled=True, use_container_width=True)


initialize_state()
render_sidebar()
if st.session_state.nav == "Command Center":
    render_command_center()
elif st.session_state.nav == "Document Analyzer":
    render_document_analyzer()
elif st.session_state.nav == "Privacy Preview":
    render_privacy_preview()
elif st.session_state.nav == "Risk Intelligence":
    render_risk_intelligence()
else:
    render_attack_lab()
