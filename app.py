from __future__ import annotations

import os

import joblib
import pandas as pd
import streamlit as st

from feature_extractor import (
    FeatureExtractionError,
    SELECTED_FEATURES,
    extract_features,
    normalize_url,
)


# ============================================================
# FILE LOCATIONS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "final_random_forest.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "selected_features.pkl")
THRESHOLD_PATH = os.path.join(BASE_DIR, "phishing_threshold.pkl")


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Phishing Website Detector",
    page_icon="🛡️",
    layout="centered",
)

st.markdown(
    """
    <style>
        .main-title {
            text-align: center;
            font-size: 2.35rem;
            font-weight: 750;
            margin-bottom: 0.25rem;
        }

        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 1.75rem;
        }

        .result-box {
            padding: 1.25rem;
            border-radius: 0.8rem;
            margin-top: 1rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# LOAD TRAINED ML ARTIFACTS
# ============================================================

@st.cache_resource
def load_system():
    required_files = [
        MODEL_PATH,
        FEATURES_PATH,
        THRESHOLD_PATH,
    ]

    missing_files = [
        os.path.basename(path)
        for path in required_files
        if not os.path.exists(path)
    ]

    if missing_files:
        raise FileNotFoundError(
            "Missing required model file(s): "
            + ", ".join(missing_files)
        )

    model = joblib.load(MODEL_PATH)
    selected_features = list(joblib.load(FEATURES_PATH))
    threshold = float(joblib.load(THRESHOLD_PATH))

    # --------------------------------------------------------
    # SAFETY CHECKS
    # --------------------------------------------------------
