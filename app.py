import os
import time

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

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "final_random_forest.pkl"
)

FEATURE_FILE = os.path.join(
    BASE_DIR,
    "selected_features.pkl"
)

THRESHOLD_FILE = os.path.join(
    BASE_DIR,
    "phishing_threshold.pkl"
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Phishing Website Detector",
    page_icon="🛡️",
    layout="centered",
)


# ============================================================
# DESIGN
# ============================================================

st.markdown(
    """
    <style>

    .block-container {
        max-width: 760px;
        padding-top: 3rem;
        padding-bottom: 3rem;
    }

    .main-title {
        text-align: center;
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 8px;
    }

    .subtitle {
        text-align: center;
        font-size: 17px;
        color: #8b8b8b;
        margin-bottom: 35px;
    }

    .result-safe {
        background: rgba(34, 197, 94, 0.10);
        border: 1px solid rgba(34, 197, 94, 0.45);
        border-radius: 14px;
        padding: 25px;
        text-align: center;
        margin-top: 20px;
    }

    .result-danger {
        background: rgba(239, 68, 68, 0.10);
        border: 1px solid rgba(239, 68, 68, 0.45);
        border-radius: 14px;
        padding: 25px;
        text-align: center;
        margin-top: 20px;
    }

    .result-title {
        font-size: 27px;
        font-weight: 800;
        margin-bottom: 8px;
    }

    .result-description {
        font-size: 16px;
    }

    div[data-testid="stTextInput"] input {
        font-size: 16px;
        padding: 12px;
    }

    div.stButton > button {
        height: 50px;
        font-size: 17px;
        font-weight: 700;
        border-radius: 10px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_system():

    model = joblib.load(
        MODEL_FILE
    )

    selected_features = joblib.load(
        FEATURE_FILE
    )

    threshold = float(
        joblib.load(
            THRESHOLD_FILE
        )
    )

    return (
        model,
        list(selected_features),
        threshold,
    )


try:

    model, selected_features, threshold = load_system()

except Exception:

    st.error(
        "The detector is currently unavailable. "
        "Please try again later."
    )

    st.stop()


# ============================================================
# INTERNAL VALIDATION
# ============================================================

if set(selected_features) != set(SELECTED_FEATURES):

    st.error(
        "The detector is currently unavailable. "
        "Please contact the administrator."
    )

    st.stop()


if hasattr(model, "n_features_in_"):

    if model.n_features_in_ != len(selected_features):

        st.error(
            "The detector is currently unavailable. "
            "Please contact the administrator."
        )

        st.stop()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="main-title">
        🛡️ Phishing Website Detector
    </div>

    <div class="subtitle">
        Check a website link before you open or trust it.
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# URL FORM
# ============================================================

with st.form(
    "url_form",
    clear_on_submit=False,
):

    url_input = st.text_input(
        "Website URL",
        placeholder="Example: https://example.com",
    )

    analyze_button = st.form_submit_button(
        "🔍 Check Website",
        type="primary",
        use_container_width=True,
    )


# ============================================================
# ANALYZE
# ============================================================

if analyze_button:

    if not url_input.strip():

        st.warning(
            "Please enter a website URL."
        )

        st.stop()


    try:

        normalized_url = normalize_url(
            url_input
        )

    except FeatureExtractionError:

        st.warning(
            "Please enter a valid website URL."
        )

        st.stop()


    # --------------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------------

    try:

        with st.spinner(
            "Checking the website..."
        ):

            features = extract_features(
                normalized_url
            )

    except Exception:

        st.error(
            "We couldn't analyze this URL. "
            "Please check the link and try again."
        )

        st.stop()


    # --------------------------------------------------------
    # PREPARE MODEL INPUT
    # --------------------------------------------------------

    try:

        input_data = pd.DataFrame(
            [features]
        )

        input_data = input_data[
            selected_features
        ]

        input_data = input_data.apply(
            pd.to_numeric,
            errors="coerce",
        )

        if input_data.isnull().any().any():

            raise ValueError(
                "Invalid feature value."
            )

    except Exception:

        st.error(
            "We couldn't analyze this URL. "
            "Please try another link."
        )

        st.stop()


    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    try:

        probabilities = model.predict_proba(
            input_data
        )[0]

        classes = list(
            model.classes_
        )

        phishing_index = classes.index(
            1
        )

        phishing_probability = float(
            probabilities[
                phishing_index
            ]
        )

        prediction = (
            1
            if phishing_probability >= threshold
            else 0
        )

    except Exception:

        st.error(
            "Something went wrong while checking the URL. "
            "Please try again."
        )

        st.stop()


    # ========================================================
    # RESULT
    # ========================================================

    if prediction == 1:

        st.markdown(
            """
            <div class="result-danger">

                <div class="result-title">
                    ⚠️ Potential Phishing Website
                </div>

                <div class="result-description">
                    This link shows characteristics commonly
                    associated with phishing websites.
                    Avoid entering passwords, payment details,
                    or personal information.
                </div>

            </div>
            """,
            unsafe_allow_html=True,
        )

    else:

        st.markdown(
            """
            <div class="result-safe">

                <div class="result-title">
                    ✅ Likely Legitimate Website
                </div>

                <div class="result-description">
                    This link does not show strong phishing
                    characteristics based on the analysis.
                </div>

            </div>
            """,
            unsafe_allow_html=True,
        )


    # ========================================================
    # SIMPLE SCORE
    # ========================================================

    st.write("")

    st.write(
        "**Phishing likelihood**"
    )

    st.progress(
        min(
            max(
                phishing_probability,
                0.0
            ),
            1.0
        )
    )

    st.caption(
        f"{phishing_probability * 100:.1f}%"
    )


# ============================================================
# FOOTER
# ============================================================

st.write("")
st.divider()

st.caption(
    "Results are provided as a security screening aid. "
    "Always be cautious with unfamiliar links."
)
