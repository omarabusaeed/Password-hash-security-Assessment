import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys
import os
import time
import base64
import platform
from datetime import datetime

# Add root directory to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.strength_analyzer import StrengthAnalyzer
from modules.hash_generator import HashGenerator
from modules.policy_recommender import PolicyRecommender
from modules.report_generator import ReportGenerator
from modules.crack_simulator import CrackSimulator

# Page Configuration
st.set_page_config(
    page_title="HashSentinel | Password Hash Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = StrengthAnalyzer()
if 'generator' not in st.session_state:
    st.session_state.generator = HashGenerator()
if 'recommender' not in st.session_state:
    st.session_state.recommender = PolicyRecommender()
if 'reporter' not in st.session_state:
    st.session_state.reporter = ReportGenerator()
if 'simulator' not in st.session_state:
    st.session_state.simulator = CrackSimulator()
if 'session_history' not in st.session_state:
    st.session_state.session_history = []
if 'last_analyzed_password' not in st.session_state:
    st.session_state.last_analyzed_password = ""

analyzer = st.session_state.analyzer
generator = st.session_state.generator
recommender = st.session_state.recommender
reporter = st.session_state.reporter
simulator = st.session_state.simulator

# Helper to record tested passwords for real-time audit report
def record_test(pwd, analysis_res):
    if not pwd:
        return
    # Check if already in history
    for item in st.session_state.session_history:
        if item['password'] == pwd:
            return
    masked = pwd[0] + ("*" * max(1, len(pwd) - 2)) + (pwd[-1] if len(pwd) > 1 else "")
    st.session_state.session_history.append({
        'password': pwd,
        'display_password': masked,
        'strength_percent': analysis_res['strength_percent'],
        'entropy': analysis_res['entropy'],
        'pwned_count': analysis_res['pwned_count'],
        'detected_names': analysis_res.get('detected_names', []),
        'nist_status': 'PASS' if analysis_res['nist_audit']['is_compliant'] else 'FAIL',
        'warning': analysis_res.get('warning', ''),
        'timestamp': datetime.now().strftime("%H:%M:%S")
    })

# ═══════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE HIGH-CONTRAST DARK THEME & SMOOTH ANIMATION STYLING
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg-main: #0B0F19;
    --surface-card: #131B2A;
    --surface-hover: #1A2438;
    --border-light: rgba(148, 163, 184, 0.18);
    --border-bright: #38BDF8;
    --brand-blue: #3B82F6;
    --brand-cyan: #06B6D4;
    --brand-emerald: #10B981;
    --brand-amber: #F59E0B;
    --brand-rose: #EF4444;
    --text-primary: #F8FAFC;
    --text-secondary: #E2E8F0;
    --text-muted: #94A3B8;
}

/* ─── Global App Typography & Theme ─── */
.stApp {
    background-color: var(--bg-main);
    font-family: 'Plus Jakarta Sans', sans-serif;
    color: var(--text-primary);
}

h1, h2, h3, h4, h5 {
    font-family: 'Plus Jakarta Sans', sans-serif !important;
    font-weight: 700 !important;
    color: #F8FAFC !important;
    letter-spacing: -0.01em !important;
}

/* Ensure ALL body, label, and span text is high-contrast readable */
.stApp p, .stApp span, .stApp label {
    color: #E2E8F0 !important;
}

label[data-testid="stWidgetLabel"] p,
.stWidgetLabel label,
.stWidgetLabel p {
    color: #F8FAFC !important;
    font-weight: 600 !important;
    font-size: 0.92rem !important;
}

/* Metric values & labels */
div[data-testid="stMetricValue"] {
    color: #FFFFFF !important;
    font-weight: 800 !important;
}
div[data-testid="stMetricLabel"] {
    color: #CBD5E1 !important;
    font-weight: 600 !important;
}
div[data-testid="stMetricDelta"] {
    color: #38BDF8 !important;
}

/* ─── Streamlit Tables (High Contrast) ─── */
.stTable table, .stTable th, .stTable td,
table, th, td {
    color: #F1F5F9 !important;
    border-color: rgba(148, 163, 184, 0.25) !important;
}
.stTable th, th {
    background-color: #1E293B !important;
    color: #38BDF8 !important;
    font-weight: 700 !important;
}
.stTable td, td {
    background-color: rgba(15, 23, 42, 0.75) !important;
}

/* ─── Card Systems ─── */
.sentinel-box {
    background: var(--surface-card);
    border: 1px solid var(--border-light);
    border-radius: 12px;
    padding: 22px;
    margin-bottom: 16px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
    transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
}

.sentinel-box:hover {
    border-color: rgba(56, 189, 248, 0.45);
    box-shadow: 0 6px 24px rgba(56, 189, 248, 0.15);
    transform: translateY(-2px);
}

.hero-welcome {
    background: linear-gradient(135deg, rgba(30, 41, 59, 0.85) 0%, rgba(15, 23, 42, 0.98) 100%);
    border: 1px solid rgba(56, 189, 248, 0.3);
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 24px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.45);
    position: relative;
    overflow: hidden;
}

/* ─── Native Bordered Containers (e.g. PDF Gen Box, Telemetry Card) ─── */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: #131B2A !important;
    border: 1px solid rgba(56, 189, 248, 0.35) !important;
    border-radius: 14px !important;
    padding: 22px !important;
    box-shadow: 0 6px 28px rgba(0, 0, 0, 0.45) !important;
    margin-bottom: 16px !important;
}

/* ─── Inputs & Textareas (Bright Text, Crisp Border) ─── */
.stTextArea textarea,
div[data-baseweb="textarea"] textarea,
.stTextArea > div > div > textarea {
    background-color: #0F172A !important;
    color: #38BDF8 !important;
    border: 1px solid rgba(56, 189, 248, 0.4) !important;
    border-radius: 8px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.92rem !important;
    padding: 12px !important;
    caret-color: #38BDF8 !important;
}

div[data-baseweb="textarea"] {
    background-color: #0F172A !important;
    border: 1px solid rgba(56, 189, 248, 0.4) !important;
    border-radius: 8px !important;
}

.stTextInput > div > div > input {
    background-color: #0F172A !important;
    color: #FFFFFF !important;
    border: 1px solid rgba(56, 189, 248, 0.4) !important;
    border-radius: 8px !important;
    font-family: 'JetBrains Mono', monospace !important;
    padding: 0 14px !important;
    height: 42px !important;
    line-height: 42px !important;
    caret-color: #38BDF8 !important;
}

.stTextInput > div > div > input::placeholder {
    color: #94A3B8 !important;
}

.stTextInput > div > div > input:focus {
    border-color: #38BDF8 !important;
    box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.35) !important;
}

/* Dropdown / Selectbox */
.stSelectbox > div > div,
div[data-baseweb="select"] > div {
    background-color: #0F172A !important;
    color: #F8FAFC !important;
    border: 1px solid rgba(56, 189, 248, 0.4) !important;
    border-radius: 8px !important;
}
div[data-baseweb="select"] span {
    color: #F8FAFC !important;
}
div[data-baseweb="popover"] ul {
    background-color: #131B2A !important;
}
div[data-baseweb="popover"] li {
    color: #F8FAFC !important;
}
div[data-baseweb="popover"] li:hover {
    background-color: #1E293B !important;
}

/* ═══════════════════════════════════════════════════════════════════════════
   BUTTONS: EXACT VERTICAL ALIGNMENT & 100% VISIBLE (NO WHITE-ON-WHITE)
   ═══════════════════════════════════════════════════════════════════════════ */
/* Align horizontally adjacent columns seamlessly */
div[data-testid="stHorizontalBlock"] {
    align-items: flex-start !important;
}
div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {
    display: flex !important;
    flex-direction: column !important;
    justify-content: flex-start !important;
}

div[data-testid="stTextInput"] {
    margin: 0 !important;
    padding: 0 !important;
}
div[data-testid="stTextInput"] > div[data-baseweb="input"] {
    height: 42px !important;
    min-height: 42px !important;
    border-radius: 8px !important;
}

div[data-testid="stButton"] {
    margin: 0 !important;
    padding: 0 !important;
}

/* Universal Button Styling: High-Visibility Glowing Cyan/Blue */
div[data-testid="stButton"] button {
    background: linear-gradient(135deg, #1E40AF 0%, #0284C7 100%) !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    font-size: 1rem !important;
    border: 1px solid #38BDF8 !important;
    border-radius: 8px !important;
    height: 42px !important;
    min-height: 42px !important;
    line-height: 42px !important;
    padding: 0 18px !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    box-shadow: 0 3px 12px rgba(2, 132, 199, 0.4) !important;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
    margin: 0 !important;
}

div[data-testid="stButton"] button:hover {
    background: linear-gradient(135deg, #2563EB 0%, #06B6D4 100%) !important;
    color: #FFFFFF !important;
    border-color: #38BDF8 !important;
    box-shadow: 0 0 18px rgba(56, 189, 248, 0.6) !important;
    transform: translateY(-1px) scale(1.01) !important;
}

div[data-testid="stButton"] button:active,
div[data-testid="stButton"] button:focus {
    background: linear-gradient(135deg, #1D4ED8 0%, #0284C7 100%) !important;
    color: #FFFFFF !important;
    border-color: #38BDF8 !important;
    box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.5) !important;
}

/* Ensure inner text and icons in all buttons are completely visible */
div[data-testid="stButton"] button * {
    color: #FFFFFF !important;
    fill: #FFFFFF !important;
    font-weight: 700 !important;
}

/* Download Button Styling */
div[data-testid="stDownloadButton"] button {
    background: linear-gradient(135deg, #059669 0%, #10B981 100%) !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    font-size: 1rem !important;
    border: 1px solid #34D399 !important;
    border-radius: 8px !important;
    padding: 12px 24px !important;
    box-shadow: 0 4px 16px rgba(16, 185, 129, 0.35) !important;
    transition: all 0.25s ease !important;
}
div[data-testid="stDownloadButton"] button:hover {
    box-shadow: 0 6px 24px rgba(52, 211, 153, 0.6) !important;
    transform: translateY(-2px) !important;
}
div[data-testid="stDownloadButton"] button * {
    color: #FFFFFF !important;
    font-weight: 700 !important;
}

/* ═══════════════════════════════════════════════════════════════════════════
   ANIMATED SIDEBAR NAVIGATION — Smooth Scroll & Fluid Kinetic Hover
   ═══════════════════════════════════════════════════════════════════════════ */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #070B14 0%, #0B101D 50%, #0E1626 100%) !important;
    border-right: 1px solid rgba(56, 189, 248, 0.12) !important;
    overflow-y: auto !important;
    scroll-behavior: smooth !important;
}

/* Custom modern scrollbar for sidebar */
section[data-testid="stSidebar"]::-webkit-scrollbar {
    width: 5px;
}
section[data-testid="stSidebar"]::-webkit-scrollbar-track {
    background: transparent;
}
section[data-testid="stSidebar"]::-webkit-scrollbar-thumb {
    background: rgba(56, 189, 248, 0.25);
    border-radius: 6px;
}
section[data-testid="stSidebar"]::-webkit-scrollbar-thumb:hover {
    background: rgba(56, 189, 248, 0.55);
}

/* Sidebar section header */
section[data-testid="stSidebar"] .stRadio > label {
    color: #94A3B8 !important;
    font-size: 0.72rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    margin-bottom: 8px !important;
}

/* Animated Radio Nav Pills */
section[data-testid="stSidebar"] div[role="radiogroup"] > label {
    background: rgba(19, 27, 42, 0.65) !important;
    border: 1px solid rgba(148, 163, 184, 0.12) !important;
    border-radius: 10px !important;
    padding: 12px 18px !important;
    margin-bottom: 8px !important;
    cursor: pointer !important;
    position: relative !important;
    overflow: hidden !important;
    backdrop-filter: blur(8px) !important;
    transition: all 0.32s cubic-bezier(0.25, 1, 0.5, 1) !important;
}

/* Dynamic Hover with Glowing Left Edge & Horizontal Shift */
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
    background: linear-gradient(90deg, rgba(30, 41, 59, 0.95) 0%, rgba(14, 116, 144, 0.22) 100%) !important;
    border-color: #38BDF8 !important;
    transform: translateX(8px) scale(1.01) !important;
    box-shadow: 0 4px 20px rgba(56, 189, 248, 0.25), inset 0 0 15px rgba(56, 189, 248, 0.08) !important;
}

/* Glowing Neon Left Border Indicator */
section[data-testid="stSidebar"] div[role="radiogroup"] > label::before {
    content: '' !important;
    position: absolute !important;
    left: 0 !important;
    top: 50% !important;
    transform: translateY(-50%) scaleY(0) !important;
    width: 4px !important;
    height: 70% !important;
    background: linear-gradient(180deg, #38BDF8, #3B82F6) !important;
    border-radius: 0 4px 4px 0 !important;
    box-shadow: 0 0 10px #38BDF8 !important;
    transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover::before {
    transform: translateY(-50%) scaleY(1) !important;
}

/* Active / Checked State */
section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"],
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) {
    background: linear-gradient(90deg, rgba(37, 99, 235, 0.35) 0%, rgba(6, 182, 212, 0.22) 100%) !important;
    border: 1px solid #38BDF8 !important;
    box-shadow: 0 0 20px rgba(56, 189, 248, 0.35), inset 0 0 12px rgba(6, 182, 212, 0.12) !important;
    transform: translateX(6px) !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"]::before,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked)::before {
    transform: translateY(-50%) scaleY(1) !important;
    background: linear-gradient(180deg, #06B6D4, #3B82F6) !important;
    box-shadow: 0 0 12px #38BDF8 !important;
}

/* Nav Typography */
section[data-testid="stSidebar"] div[role="radiogroup"] > label p,
section[data-testid="stSidebar"] div[role="radiogroup"] > label span {
    color: #E2E8F0 !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    transition: color 0.25s ease !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover p,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:hover span {
    color: #FFFFFF !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] p,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) p,
section[data-testid="stSidebar"] div[role="radiogroup"] > label[data-checked="true"] span,
section[data-testid="stSidebar"] div[role="radiogroup"] > label:has(input:checked) span {
    color: #FFFFFF !important;
    font-weight: 700 !important;
}

/* ─── Status Badges ─── */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 700;
}
.pill-safe { background: rgba(16, 185, 129, 0.2); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.4); }
.pill-danger { background: rgba(239, 68, 68, 0.2); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.4); }
.pill-warn { background: rgba(245, 158, 11, 0.2); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.4); }
.pill-info { background: rgba(59, 130, 246, 0.2); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.4); }

/* ─── Code Blocks ─── */
.stCodeBlock, code, pre {
    background-color: #0F172A !important;
    color: #38BDF8 !important;
    border: 1px solid rgba(148, 163, 184, 0.18) !important;
    border-radius: 6px !important;
}

/* ─── Alerts & Callouts ─── */
.stAlert > div {
    color: #F8FAFC !important;
    border-radius: 8px !important;
}
.stAlert > div p {
    color: #F8FAFC !important;
}
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    # Visible Native Circular Emblem PNG (Fixes broken circle image)
    logo_path = os.path.join(CURRENT_DIR, "assets", "circle_shield_logo.png")
    if os.path.exists(logo_path):
        col_l1, col_l2, col_l3 = st.columns([1, 2, 1])
        with col_l2:
            st.image(logo_path, width=95)
    else:
        st.markdown('<div style="text-align: center; font-size: 3.5rem;">🛡️</div>', unsafe_allow_html=True)

    st.markdown("""
        <div style="text-align: center; margin-bottom: 20px;">
            <div style="font-size: 1.35rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.02em;">
                HASHSENTINEL
            </div>
            <div style="font-size: 0.75rem; color: #38BDF8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em;">
                Password Security & Hash Lab
            </div>
        </div>
    """, unsafe_allow_html=True)

    st.markdown("<hr style='border: 0; border-top: 1px solid rgba(148, 163, 184, 0.12); margin: 10px 0 16px 0;'>", unsafe_allow_html=True)

    # Clean, Streamlined Workspaces with Smooth Animations
    menu = st.radio(
        "PLATFORM WORKSPACES",
        [
            "🏠 Security Dashboard",
            "🔍 Password Strength & Name Checker",
            "⚡ Hash Generator & Converter",
            "🔎 Hash Inspector & Deconstructor",
            "🎯 Visual Cracking & Salt Demo",
            "📑 Real-Time Audit Report"
        ]
    )

    st.markdown("<hr style='border: 0; border-top: 1px solid rgba(148, 163, 184, 0.12); margin: 20px 0;'>", unsafe_allow_html=True)

    # Session Activity Summary in Sidebar
    session_count = len(st.session_state.session_history)
    st.markdown(f"""
        <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(148, 163, 184, 0.18); border-radius: 8px; padding: 12px; font-size: 0.78rem;">
            <div style="color: #94A3B8; font-weight: 700; margin-bottom: 8px; letter-spacing: 0.05em;">SESSION TELEMETRY</div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                <span style="color: #CBD5E1;">Passwords Analyzed:</span>
                <span style="color: #38BDF8; font-weight: 700;">{session_count}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                <span style="color: #CBD5E1;">Breach Engine:</span>
                <span style="color: #34D399; font-weight: 700;">ACTIVE (HIBP)</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #CBD5E1;">Name Dictionary:</span>
                <span style="color: #34D399; font-weight: 700;">LOADED</span>
            </div>
        </div>
    """, unsafe_allow_html=True)

# ==============================================================================
# 1. SECURITY DASHBOARD (USER-FRIENDLY & PROFESSIONAL)
# ==============================================================================
if menu == "🏠 Security Dashboard":
    # Modern Friendly Hero Welcome
    st.markdown("""
        <div class="hero-welcome">
            <div style="display: inline-block; padding: 4px 12px; border-radius: 20px; background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.35); color: #38BDF8; font-size: 0.8rem; font-weight: 700; margin-bottom: 12px;">
                ● ENTERPRISE SECURITY PORTAL
            </div>
            <div style="font-size: 2.1rem; font-weight: 800; color: #FFFFFF; line-height: 1.2;">
                Password Hash Security & Vulnerability Assessment
            </div>
            <div style="font-size: 1rem; color: #CBD5E1; margin-top: 8px; max-width: 800px; line-height: 1.5;">
                Evaluate password entropy, detect personal name vulnerabilities, convert plaintext into military-grade hashes, and audit authentication resilience in real-time.
            </div>
        </div>
    """, unsafe_allow_html=True)

    # 4 Quick Pillar Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown("""
            <div class="sentinel-box">
                <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">Primary Protection</div>
                <div style="font-size: 1.6rem; font-weight: 800; color: #34D399; margin: 4px 0;">Argon2id</div>
                <div style="font-size: 0.8rem; color: #CBD5E1;">Memory-hard PHC Winner</div>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
            <div class="sentinel-box">
                <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">Breach Database</div>
                <div style="font-size: 1.6rem; font-weight: 800; color: #38BDF8; margin: 4px 0;">10.4B+ Records</div>
                <div style="font-size: 0.8rem; color: #CBD5E1;">Live K-Anonymity HIBP</div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
            <div class="sentinel-box">
                <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">High-Risk Hashes</div>
                <div style="font-size: 1.6rem; font-weight: 800; color: #F87171; margin: 4px 0;">MD5 & SHA-1</div>
                <div style="font-size: 0.8rem; color: #CBD5E1;">Cracked in &lt; 1 millisecond</div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown("""
            <div class="sentinel-box">
                <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700; text-transform: uppercase;">Global Standard</div>
                <div style="font-size: 1.6rem; font-weight: 800; color: #818CF8; margin: 4px 0;">NIST SP 800-63B</div>
                <div style="font-size: 0.8rem; color: #CBD5E1;">Digital Identity Guidelines</div>
            </div>
        """, unsafe_allow_html=True)

    # Friendly Instant Password Test with Pixel-Perfect Arrow Button
    st.markdown("### ⚡ Quick Password Security Test")
    st.markdown('<p style="color: #CBD5E1; font-size: 0.95rem;">Screen any candidate password for personal name exposure, breach status, and entropy strength.</p>', unsafe_allow_html=True)

    col_box, col_btn = st.columns([5, 1])
    with col_box:
        quick_pwd = st.text_input("Enter password to test", type="password", placeholder="e.g. Type your password or test a name like Omar...", label_visibility="collapsed", key="dash_quick_input")
    with col_btn:
        arrow_clicked = st.button("➔ Enter", key="dash_arrow_btn", help="Click to test password", use_container_width=True)

    if quick_pwd or arrow_clicked:
        target = quick_pwd if quick_pwd else st.session_state.last_analyzed_password
        if target:
            res = analyzer.analyze(target)
            record_test(target, res)
            
            r1, r2, r3 = st.columns(3)
            with r1:
                st.metric("Integrity Score", f"{res['strength_percent']}%", delta=f"{res['entropy']} bits entropy")
            with r2:
                pwn_str = f"Found in {res['pwned_count']:,} Breaches" if res['pwned_count'] > 0 else "Clean (0 Breaches)"
                st.metric("Breach Exposure", pwn_str)
            with r3:
                name_status = f"Name Found: {', '.join(res['detected_names'][:2])}" if res['detected_names'] else "No Names Found"
                st.metric("Dictionary / Name Check", name_status)

            if res['warning']:
                st.error(res['warning'])
            else:
                st.success("✔ Password demonstrates strong cryptographic entropy and no dictionary patterns.")

    # Algorithm Safety Guide
    st.markdown("---")
    st.markdown("### 🛡️ Algorithm Safety & Migration Guide")
    st.markdown('<p style="color: #CBD5E1; font-size: 0.95rem;">Understand which password storage algorithms protect your users and which leave them defenseless.</p>', unsafe_allow_html=True)

    g1, g2, g3, g4 = st.columns(4)
    with g1:
        st.markdown("""
            <div class="sentinel-box" style="border-left: 4px solid #EF4444;">
                <span class="status-pill pill-danger">FATALLY BROKEN</span>
                <div style="font-size: 1.25rem; font-weight: 700; color: #FFFFFF; margin: 8px 0;">MD5 & SHA-1</div>
                <div style="font-size: 0.85rem; color: #CBD5E1; line-height: 1.45;">Modern GPUs test 300+ billion guesses per second. Never store passwords with these legacy algorithms.</div>
            </div>
        """, unsafe_allow_html=True)
    with g2:
        st.markdown("""
            <div class="sentinel-box" style="border-left: 4px solid #F59E0B;">
                <span class="status-pill pill-warn">UNSAFE FOR PASSWORDS</span>
                <div style="font-size: 1.25rem; font-weight: 700; color: #FFFFFF; margin: 8px 0;">Raw SHA-256</div>
                <div style="font-size: 0.85rem; color: #CBD5E1; line-height: 1.45;">Excellent for file integrity, but dangerously fast for passwords without salt and key stretching.</div>
            </div>
        """, unsafe_allow_html=True)
    with g3:
        st.markdown("""
            <div class="sentinel-box" style="border-left: 4px solid #3B82F6;">
                <span class="status-pill pill-info">ENTERPRISE STANDARD</span>
                <div style="font-size: 1.25rem; font-weight: 700; color: #FFFFFF; margin: 8px 0;">bcrypt</div>
                <div style="font-size: 0.85rem; color: #CBD5E1; line-height: 1.45;">Built-in random salting with configurable CPU work factor. Battle-tested across millions of web applications.</div>
            </div>
        """, unsafe_allow_html=True)
    with g4:
        st.markdown("""
            <div class="sentinel-box" style="border-left: 4px solid #10B981;">
                <span class="status-pill pill-safe">GOLD STANDARD</span>
                <div style="font-size: 1.25rem; font-weight: 700; color: #FFFFFF; margin: 8px 0;">Argon2id</div>
                <div style="font-size: 0.85rem; color: #CBD5E1; line-height: 1.45;">Winner of the Password Hashing Competition (RFC 9106). Requires large RAM memory to defeat GPU & ASIC clusters.</div>
            </div>
        """, unsafe_allow_html=True)

# ==============================================================================
# 2. PASSWORD STRENGTH & NAME CHECKER (WITH NAME DICTIONARY)
# ==============================================================================
elif menu == "🔍 Password Strength & Name Checker":
    st.title("🔍 Password Strength & Dictionary Name Checker")
    st.markdown('<p style="color: #CBD5E1; font-size: 0.95rem;">Scan candidate passwords for dictionary names, personal identifiers, entropy depth, and public breach leaks.</p>', unsafe_allow_html=True)

    # Text Input with Enter / Arrow Button
    st.markdown("#### Enter Candidate Password")
    col_in, col_go = st.columns([5, 1])
    with col_in:
        pwd_input = st.text_input(
            "Input Password",
            type="password",
            placeholder="Type password to analyze (try names like Omar, OmarAbuSaeed, or test passwords)...",
            label_visibility="collapsed",
            key="strength_pwd_input"
        )
    with col_go:
        btn_scan = st.button("➔ Scan", key="btn_strength_scan", use_container_width=True)

    if pwd_input or btn_scan:
        target = pwd_input
        st.session_state.last_analyzed_password = target
        res = analyzer.analyze(target)
        record_test(target, res)

        # Gauge & Metric Cards Row
        c_left, c_right = st.columns([1.2, 1.8])
        with c_left:
            bar_color = "#EF4444" if res['strength_percent'] < 40 else ("#F59E0B" if res['strength_percent'] < 75 else "#10B981")
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=res['strength_percent'],
                number={'suffix': "%", 'font': {'size': 44, 'family': 'Plus Jakarta Sans', 'color': '#FFFFFF'}},
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "SECURITY INTEGRITY", 'font': {'size': 15, 'family': 'Plus Jakarta Sans', 'color': '#CBD5E1'}},
                gauge={
                    'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
                    'bar': {'color': bar_color, 'thickness': 0.28},
                    'bgcolor': "#0F172A",
                    'borderwidth': 1,
                    'bordercolor': "#334155",
                    'steps': [
                        {'range': [0, 35], 'color': 'rgba(239, 68, 68, 0.15)'},
                        {'range': [35, 75], 'color': 'rgba(245, 158, 11, 0.15)'},
                        {'range': [75, 100], 'color': 'rgba(16, 185, 129, 0.15)'}
                    ]
                }
            ))
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"}, height=240, margin=dict(l=20, r=20, t=35, b=20))
            st.plotly_chart(fig, width="stretch")

        with c_right:
            k1, k2 = st.columns(2)
            with k1:
                st.markdown(f"""
                    <div class="sentinel-box">
                        <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700;">ENTROPY SCORE</div>
                        <div style="font-size: 1.8rem; font-weight: 800; color: #38BDF8;">{res['entropy']} <span style="font-size: 0.9rem; color: #94A3B8;">bits</span></div>
                        <div style="font-size: 0.8rem; color: #CBD5E1;">Theoretical keyspace size</div>
                    </div>
                """, unsafe_allow_html=True)
            with k2:
                pwn_color = "#34D399" if res['pwned_count'] == 0 else "#F87171"
                st.markdown(f"""
                    <div class="sentinel-box">
                        <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700;">HIBP BREACH LEAKS</div>
                        <div style="font-size: 1.8rem; font-weight: 800; color: {pwn_color};">{res['pwned_count']:,}</div>
                        <div style="font-size: 0.8rem; color: #CBD5E1;">Public credential dumps</div>
                    </div>
                """, unsafe_allow_html=True)

            k3, k4 = st.columns(2)
            with k3:
                name_badge = f'<span class="status-pill pill-danger">DETECTED ({", ".join(res["detected_names"][:2])})</span>' if res['detected_names'] else '<span class="status-pill pill-safe">NO NAMES FOUND</span>'
                st.markdown(f"""
                    <div class="sentinel-box">
                        <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700;">PERSONAL NAME CHECK</div>
                        <div style="margin-top: 6px;">{name_badge}</div>
                        <div style="font-size: 0.8rem; color: #CBD5E1; margin-top: 8px;">Guards against targeted OSINT</div>
                    </div>
                """, unsafe_allow_html=True)
            with k4:
                nist_badge = '<span class="status-pill pill-safe">COMPLIANT</span>' if res['nist_audit']['is_compliant'] else '<span class="status-pill pill-danger">NON-COMPLIANT</span>'
                st.markdown(f"""
                    <div class="sentinel-box">
                        <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700;">NIST SP 800-63B</div>
                        <div style="margin-top: 6px;">{nist_badge}</div>
                        <div style="font-size: 0.8rem; color: #CBD5E1; margin-top: 8px;">NIST Digital Identity Guideline</div>
                    </div>
                """, unsafe_allow_html=True)

        # Warning / Hazards
        if res['warning']:
            st.error(f"⚠️ **HAZARD:** {res['warning']}")
        for f in res['feedback']:
            st.info(f"💡 {f}")

        # Hardware Crack Time Matrix
        st.markdown("---")
        st.markdown("### ⏱️ Estimated Time to Crack This Password")
        st.markdown('<p style="color: #CBD5E1;">Notice how fast hashes (MD5) fall instantly, while adaptive hashes (bcrypt/Argon2) withstand attacks.</p>', unsafe_allow_html=True)
        
        crack_table = pd.DataFrame(res['hardware_estimates'])[['tier', 'specs', 'time_fast_hash', 'time_bcrypt', 'time_argon2']]
        crack_table.columns = ['Attacker Profile', 'Hardware Specs', 'Fast Hash (MD5 / SHA-256)', 'bcrypt (Cost 12)', 'Argon2id (64MB)']
        st.table(crack_table)

        # Recommended Alternatives
        st.markdown("---")
        st.markdown("### 🔐 Stronger Cryptographic Alternatives")
        st.markdown('<p style="color: #CBD5E1;">NIST SP 800-63B recommends memorable 4-word passphrases over complex, easily forgotten arbitrary substitutions.</p>', unsafe_allow_html=True)
        
        alts = res.get('smart_alternatives', {})
        if alts:
            ac1, ac2 = st.columns(2)
            with ac1:
                st.markdown(f"""
                    <div class="sentinel-box">
                        <span class="status-pill pill-safe">NIST PASSPHRASE</span>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.25rem; font-weight: 700; color: #34D399; margin: 10px 0;">
                            {alts['passphrase']['value']}
                        </div>
                        <div style="font-size: 0.85rem; color: #CBD5E1;"><strong style="color: #FFFFFF;">Entropy:</strong> {alts['passphrase']['entropy']} bits | High memorability, extreme resistance.</div>
                    </div>
                """, unsafe_allow_html=True)
            with ac2:
                st.markdown(f"""
                    <div class="sentinel-box">
                        <span class="status-pill pill-info">RANDOM TOKEN</span>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.25rem; font-weight: 700; color: #38BDF8; margin: 10px 0;">
                            {alts['token']['value']}
                        </div>
                        <div style="font-size: 0.85rem; color: #CBD5E1;"><strong style="color: #FFFFFF;">Entropy:</strong> {alts['token']['entropy']} bits | Ideal for password managers and API keys.</div>
                    </div>
                """, unsafe_allow_html=True)
    else:
        st.info("👋 Type a password above and click the **➔ Scan** button to run security analysis.")

# ==============================================================================
# 3. HASH GENERATOR & CONVERTER
# ==============================================================================
elif menu == "⚡ Hash Generator & Converter":
    st.title("⚡ Cryptographic Hash Generator & Converter")
    st.markdown('<p style="color: #CBD5E1; font-size: 0.95rem;">Convert any plaintext password into modern and legacy cryptographic hash formats.</p>', unsafe_allow_html=True)

    col_h_in, col_h_go = st.columns([5, 1])
    with col_h_in:
        hash_input = st.text_input("Plaintext to Hash", "EnterpriseKey#2026", label_visibility="collapsed", key="hash_gen_input")
    with col_h_go:
        gen_btn = st.button("➔ Hash", key="btn_gen_hash", use_container_width=True)

    if hash_input:
        hashes = generator.generate_all_hashes(hash_input)
        
        st.markdown("#### Generated Hash Representations")
        for k, v in hashes.items():
            pill_class = "pill-safe" if "RECOMMENDED" in v['status'] or "GOLD" in v['status'] else ("pill-danger" if "BROKEN" in v['status'] else "pill-warn")
            st.markdown(f"""
                <div class="sentinel-box" style="padding: 18px 22px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 700; font-size: 1.08rem; color: #FFFFFF;">{v['name']}</span>
                        <span class="status-pill {pill_class}">{v['status']}</span>
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #38BDF8; margin: 10px 0; word-break: break-all; background: rgba(15, 23, 42, 0.8); padding: 10px 14px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.25);">
                        {v['hash']}
                    </div>
                    <div style="font-size: 0.82rem; color: #CBD5E1;">{v['description']}</div>
                </div>
            """, unsafe_allow_html=True)

# ==============================================================================
# 4. HASH INSPECTOR & DECONSTRUCTOR
# ==============================================================================
elif menu == "🔎 Hash Inspector & Deconstructor":
    st.title("🔎 Hash Inspector & Deconstructor")
    st.markdown('<p style="color: #CBD5E1; font-size: 0.95rem;">Paste any unknown hash string to identify its algorithm, extract embedded salts and cost parameters, and determine its vulnerability.</p>', unsafe_allow_html=True)

    st.markdown("#### Paste Target Hash String Below")
    sample_decon = st.text_area(
        "Hash Input Box",
        "$argon2id$v=19$m=65536,t=2,p=1$w25zN6XGg6hT$Jg5oFwD2Z1x0e4s9L8k7j6h5g4f3d2s1...",
        height=120,
        label_visibility="collapsed",
        key="decon_textarea"
    )

    decon_go = st.button("➔ Deconstruct Hash", key="btn_decon_go", use_container_width=True)

    if sample_decon:
        parsed = generator.deconstruct_hash(sample_decon)
        
        d1, d2, d3 = st.columns(3)
        with d1:
            st.markdown(f"""
                <div class="sentinel-box">
                    <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700;">DETECTED ALGORITHM</div>
                    <div style="font-size: 1.5rem; font-weight: 800; color: #38BDF8; margin: 4px 0;">{parsed['detected_algo']}</div>
                    <div style="font-size: 0.8rem; color: #CBD5E1;">{parsed['category']}</div>
                </div>
            """, unsafe_allow_html=True)
        with d2:
            st.markdown(f"""
                <div class="sentinel-box">
                    <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700;">SALT PRESENCE</div>
                    <div style="font-size: 1.5rem; font-weight: 800; color: #34D399; margin: 4px 0;">{'YES (Embedded)' if parsed['salt_present'] else 'NO (Unsalted)'}</div>
                    <div style="font-size: 0.8rem; color: #CBD5E1;">Salt: {parsed['salt'][:14]}...</div>
                </div>
            """, unsafe_allow_html=True)
        with d3:
            rating_color = "#34D399" if "GOLD" in parsed['security_tier'] or "REC" in parsed['security_tier'] else "#F87171"
            st.markdown(f"""
                <div class="sentinel-box">
                    <div style="font-size: 0.8rem; color: #94A3B8; font-weight: 700;">SECURITY CLASSIFICATION</div>
                    <div style="font-size: 1.5rem; font-weight: 800; color: {rating_color}; margin: 4px 0;">{parsed['security_tier']}</div>
                    <div style="font-size: 0.8rem; color: #CBD5E1;">Work Factor: {parsed['work_factor']}</div>
                </div>
            """, unsafe_allow_html=True)

        st.info(f"📋 **Forensic Breakdown:** {parsed['summary']}")

        # Adversary Tool Identification (Hashcat & John the Ripper Profile)
        hcat = parsed.get('hashcat_mode', 'N/A')
        john = parsed.get('john_format', 'N/A')
        st.markdown(f"""
            <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 16px; margin: 16px 0;">
                <div style="font-size: 0.88rem; font-weight: 800; color: #38BDF8; margin-bottom: 8px; letter-spacing: 0.04em;">⚔️ ADVERSARY AUDIT: TOOL MAPPING (HASHCAT & JOHN THE RIPPER)</div>
                <div style="display: flex; gap: 24px; flex-wrap: wrap;">
                    <div><span style="color: #CBD5E1; font-size: 0.85rem;">Hashcat Target Mode:</span> <code style="color: #38BDF8; background: #1E293B; padding: 4px 10px; border-radius: 6px; font-weight: 700;">{hcat}</code></div>
                    <div><span style="color: #CBD5E1; font-size: 0.85rem;">John the Ripper Target Format:</span> <code style="color: #34D399; background: #1E293B; padding: 4px 10px; border-radius: 6px; font-weight: 700;">{john}</code></div>
                </div>
            </div>
        """, unsafe_allow_html=True)

# ==============================================================================
# 5. VISUAL CRACKING & SALT DEMO
# ==============================================================================
elif menu == "🎯 Visual Cracking & Salt Demo":
    st.title("🎯 Visual Cracking & The Salt Defense Proof")
    st.markdown('<p style="color: #CBD5E1; font-size: 0.95rem;">Understand why unsalted hashes are cracked in milliseconds and how modern cryptographic salts protect user passwords.</p>', unsafe_allow_html=True)

    st.markdown("### 🛡️ Why Cryptographic Salts Defeat Rainbow Tables")
    st.markdown('<p style="color: #CBD5E1;">Test what happens when the exact same password is hash-generated 3 separate times:</p>', unsafe_allow_html=True)
    
    col_s_in, col_s_go = st.columns([5, 1])
    with col_s_in:
        test_plain = st.text_input("Password For Experiment", "EnterprisePassword#2026", label_visibility="collapsed", key="salt_experiment_input")
    with col_s_go:
        salt_go = st.button("➔ Test", key="btn_salt_go", use_container_width=True)

    if test_plain:
        demo = simulator.demonstrate_salt_defense(test_plain)
        
        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown("""
                <div class="sentinel-box" style="border-top: 4px solid #EF4444;">
                    <span class="status-pill pill-danger">❌ UNSALTED MD5 (VULNERABLE)</span>
                    <div style="margin: 12px 0; font-size: 0.88rem; color: #CBD5E1;">All 3 hashes generated for this password are 100% IDENTICAL:</div>
            """, unsafe_allow_html=True)
            for h in demo['unsalted_md5']['hashes']:
                st.code(h, language="text")
            st.error("⚠️ **CRITICAL FLAW:** Attackers precompute MD5 into 'Rainbow Tables' and reverse passwords instantly.")
            st.markdown("</div>", unsafe_allow_html=True)

        with c_right:
            st.markdown("""
                <div class="sentinel-box" style="border-top: 4px solid #10B981;">
                    <span class="status-pill pill-safe">✔️ SALTED ARGON2 / BCRYPT (SECURE)</span>
                    <div style="margin: 12px 0; font-size: 0.88rem; color: #CBD5E1;">All 3 hashes generated for this password are COMPLETELY UNIQUE:</div>
            """, unsafe_allow_html=True)
            for h in demo['salted_argon2']['hashes']:
                st.code(h[:50] + "...", language="text")
            st.success("🛡️ **DEFENSE IN ACTION:** Every hash contains a unique 128-bit random salt, making Rainbow Tables mathematically useless.")
            st.markdown("</div>", unsafe_allow_html=True)

        # Adversary Tool Mapping Reference Matrix
        st.markdown("---")
        st.markdown("### ⚔️ Adversary Cracking Profile (Hashcat & John the Ripper Audit Matrix)")
        st.markdown('<p style="color: #CBD5E1;">How modern adversaries target each cryptographic algorithm using Hashcat and John the Ripper, evaluated against an enterprise adversary cluster (8x NVIDIA RTX 4090 GPUs):</p>', unsafe_allow_html=True)

        tool_matrix = pd.DataFrame([
            {
                "Algorithm": "MD5",
                "Hashcat Mode": "-m 0",
                "John the Ripper Format": "--format=raw-md5",
                "Adversary Cluster Throughput": "360 GH/s (360 Billion/s)",
                "Compromise Feasibility": "Instant (< 1 ms)",
                "Audit Classification": "FATALLY BROKEN"
            },
            {
                "Algorithm": "SHA-1",
                "Hashcat Mode": "-m 100",
                "John the Ripper Format": "--format=raw-sha1",
                "Adversary Cluster Throughput": "115 GH/s (115 Billion/s)",
                "Compromise Feasibility": "Instant (< 5 ms)",
                "Audit Classification": "CRITICAL"
            },
            {
                "Algorithm": "SHA-256",
                "Hashcat Mode": "-m 1400",
                "John the Ripper Format": "--format=raw-sha256",
                "Adversary Cluster Throughput": "80 GH/s (80 Billion/s)",
                "Compromise Feasibility": "Minutes to Hours",
                "Audit Classification": "UNSAFE FOR PASSWORDS"
            },
            {
                "Algorithm": "bcrypt",
                "Hashcat Mode": "-m 3200",
                "John the Ripper Format": "--format=bcrypt",
                "Adversary Cluster Throughput": "1.2 MH/s (1.2 Million/s)",
                "Compromise Feasibility": "Decades (Adaptive Cost)",
                "Audit Classification": "RECOMMENDED"
            },
            {
                "Algorithm": "Argon2id",
                "Hashcat Mode": "-m 12100",
                "John the Ripper Format": "--format=argon2",
                "Adversary Cluster Throughput": "16 kH/s (16 Thousand/s)",
                "Compromise Feasibility": "Centuries (Memory-Hard)",
                "Audit Classification": "GOLD STANDARD"
            }
        ])
        st.table(tool_matrix)

# ==============================================================================
# 6. REAL-TIME AUDIT REPORT (PERSONALLY CUSTOMIZED FOR USER'S EXACT INPUTS)
# ==============================================================================
elif menu == "📑 Real-Time Audit Report":
    st.title("📑 Real-Time Security Audit Report")
    st.markdown('<p style="color: #CBD5E1; font-size: 0.95rem;">Generate a personalized, corporate-grade PDF audit report based on <strong style="color: #FFFFFF;">your actual tested passwords and session activity</strong>.</p>', unsafe_allow_html=True)

    col_form, col_act = st.columns([1.2, 1.8])

    # Left Column: Prominently Boxed Audit Configuration Station
    with col_form:
        with st.container(border=True):
            st.markdown("""
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 14px;">
                    <span style="font-size: 1.3rem;">📄</span>
                    <span style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF;">Audit Scope & Metadata</span>
                </div>
            """, unsafe_allow_html=True)
            client_name = st.text_input("Client / Organization Name", "Omar Abu Saeed - Security Assessment", key="pdf_client_name")
            sensitivity = st.selectbox("Document Classification", ["Confidential", "Internal Use Only", "Restricted", "Top Secret"], key="pdf_classification")
            auditor = st.text_input("Lead Assessor Name", "Principal Cryptographic Assessor", key="pdf_auditor")

            st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)
            btn_build_report = st.button("➔ Generate Real-Time Audit Report (PDF)", key="btn_gen_pdf", use_container_width=True)

    # Right Column: Live Session Credential Telemetry Box
    with col_act:
        with st.container(border=True):
            st.markdown("""
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 14px;">
                    <span style="font-size: 1.3rem;">📊</span>
                    <span style="font-size: 1.15rem; font-weight: 800; color: #FFFFFF;">Active Session Credential Telemetry</span>
                </div>
            """, unsafe_allow_html=True)
            session_list = st.session_state.session_history

            if session_list:
                st.markdown(f'<p style="color: #CBD5E1;">Found <strong style="color: #38BDF8;">{len(session_list)}</strong> credential test(s) recorded in this active session:</p>', unsafe_allow_html=True)
                for item in session_list:
                    status_color = "#F87171" if item['strength_percent'] < 40 or item['detected_names'] or item['pwned_count'] > 0 else "#34D399"
                    names_text = f" | Name Match: {', '.join(item['detected_names'])}" if item['detected_names'] else ""
                    st.markdown(f"""
                        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 10px 14px; margin-bottom: 8px; font-size: 0.88rem;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-family: 'JetBrains Mono', monospace; color: #FFFFFF; font-weight: 700;">{item['display_password']}</span>
                                <span style="color: {status_color}; font-weight: 800;">{item['strength_percent']}%</span>
                            </div>
                            <div style="font-size: 0.78rem; color: #CBD5E1; margin-top: 4px;">
                                Entropy: <strong style="color: #38BDF8;">{item['entropy']} bits</strong> | Breaches: <strong style="color: #F87171;">{item['pwned_count']}</strong>{names_text}
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.info("ℹ️ No passwords tested in this session yet. Go to **'Password Strength & Name Checker'** to test passwords, or click Generate to create an architectural baseline audit.")

    # PDF Generation Trigger & Download Section
    if btn_build_report or os.path.exists("reports/security_report.pdf"):
        if btn_build_report:
            with st.spinner("Compiling real-time session audit and rendering multi-page PDF..."):
                pdf_path = reporter.generate_report(
                    company_name=client_name,
                    sensitivity=sensitivity,
                    auditor_name=auditor,
                    session_items=st.session_state.session_history
                )
        else:
            pdf_path = "reports/security_report.pdf"

        if os.path.exists(pdf_path):
            st.markdown("---")
            with st.container(border=True):
                st.markdown(f"""
                    <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
                        <div>
                            <div style="color: #34D399; font-weight: 800; font-size: 1.15rem;">✔ Professional Audit Report Ready!</div>
                            <div style="color: #CBD5E1; font-size: 0.88rem; margin-top: 3px;">
                                Generated for: <strong style="color: #FFFFFF;">{client_name}</strong> | Standards: NIST SP 800-63B, OWASP ASVS, RFC 9106
                            </div>
                        </div>
                    </div>
                """, unsafe_allow_html=True)
                st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
                
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
                    st.download_button(
                        label=f"📥 DOWNLOAD CORPORATE AUDIT REPORT (PDF - {len(pdf_bytes)/1024:.1f} KB)",
                        data=pdf_bytes,
                        file_name=f"HashSentinel_Audit_{client_name.replace(' ', '_')}.pdf",
                        mime="application/pdf",
                        key="download_pdf_btn"
                    )

# ═══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("<hr style='border: 0; border-top: 1px solid rgba(148, 163, 184, 0.15); margin: 30px 0 15px 0;'>", unsafe_allow_html=True)
st.markdown(f"""
    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.78rem; color: #94A3B8;">
        <div><strong style="color: #CBD5E1;">HASHSENTINEL</strong> | PASSWORD HASH SECURITY SUITE</div>
        <div>STANDARDS: NIST SP 800-63B &bull; RFC 9106 ARGON2 &bull; OWASP TOP 10</div>
        <div>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
""", unsafe_allow_html=True)
