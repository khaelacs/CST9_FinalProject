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
# CUSTOM DESIGN
# ============================================================

st.markdown(
    """
<style>

.block-container {
    max-width: 780px;
    padding-top: 3rem;
    padding-bottom: 3rem;
}

/* HEADER */

.main-title {
    text-align: center;
    font-size: 46px;
    font-weight: 800;
    margin-bottom: 5px;
}

.subtitle {
    text-align: center;
    font-size: 18px;
    color: #8b8b8b;
    margin-bottom: 40px;
}

/* INPUT */

div[data-testid="stTextInput"] input {
    font-size: 17px;
    padding: 14px;
    border-radius: 10px;
}

/* BUTTON */

div.stButton > button,
div[data-testid="stFormSubmitButton"] > button {
    height: 52px;
    font-size: 17px;
    font-weight: 700;
    border-radius: 10px;
}

/* RESULT CARDS */

.safe-card {
    background: rgba(34, 197, 94, 0.08);
    border: 1px solid rgba(34, 197, 94, 0.45);
    border-radius: 16px;
    padding: 30px;
    margin-top: 25px;
}

.danger-card {
    background: rgba(239, 68, 68, 0.08);
    border: 1px solid rgba(239, 68, 68, 0.50);
    border-radius: 16px;
    padding: 30px;
    margin-top: 25px;
}

.result-icon {
    text-align: center;
    font-size: 45px;
    margin-bottom: 8px;
}

.result-title {
    text-align: center;
    font-size: 27px;
    font-weight: 800;
    margin-bottom: 12px;
}

.result-message {
    text-align: center;
    font-size: 16px;
    line-height: 1.6;
    color: #bdbdbd;
}

.advice-box {
    margin-top: 20px;
    padding: 18px;
    border-radius: 10px;
    background: rgba(255,255,255,0.04);
}

.advice-title {
    font-size: 16px;
    font-weight: 700;
    margin-bottom: 8px;
}

.footer-text {
    text-align: center;
    font-size: 13px;
    color: #777;
    margin-top: 25px;
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

    selected_features = list(
        joblib.load(
            FEATURE_FILE
        )
    )

    threshold = float(
        joblib.load(
            THRESHOLD_FILE
        )
    )

    return (
        model,
        selected_features,
        threshold,
    )


try:

    (
        model,
        selected_features,
        threshold
    ) = load_system()

except Exception:

    st.error(
        "The detector is currently unavailable. "
        "Please try again later."
    )

    st.stop()


# ============================================================
# INTERNAL CHECK
# ============================================================

if set(selected_features) != set(SELECTED_FEATURES):

    st.error(
        "The detector is currently unavailable."
    )

    st.stop()


if hasattr(
    model,
    "n_features_in_"
):

    if model.n_features_in_ != len(
        selected_features
    ):

        st.error(
            "The detector is currently unavailable."
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
Check suspicious links before trusting them.
</div>
""",
    unsafe_allow_html=True,
)


# ============================================================
# URL INPUT
# ============================================================

with st.form(
    "url_form",
    clear_on_submit=False,
):

    url_input = st.text_input(
        "Website URL",
        placeholder="https://example.com",
    )

    analyze_button = st.form_submit_button(
        "🔍 Check Website",
        type="primary",
        use_container_width=True,
    )


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    if not url_input.strip():

        st.warning(
            "Please enter a website URL."
        )

        st.stop()


    # --------------------------------------------------------
    # NORMALIZE URL
    # --------------------------------------------------------

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
    # EXTRACT FEATURES
    # --------------------------------------------------------

    try:

        with st.spinner(
            "Checking the link..."
        ):

            features = extract_features(
                normalized_url
            )

    except Exception:

        st.error(
            "We couldn't analyze this link. "
            "Please check the URL and try again."
        )

        st.stop()


    # --------------------------------------------------------
    # CREATE MODEL INPUT
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
                "Invalid input."
            )

    except Exception:

        st.error(
            "We couldn't analyze this link."
        )

        st.stop()


    # --------------------------------------------------------
    # RANDOM FOREST PREDICTION
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
            "Something went wrong while checking "
            "the link. Please try again."
        )

        st.stop()


    # ========================================================
    # DISPLAY RESULT
    # ========================================================

    if prediction == 1:

        st.markdown(
            """
<div class="danger-card">

<div class="result-icon">⚠️</div>

<div class="result-title">
Potential Phishing Website
</div>

<div class="result-message">
This link shows characteristics commonly associated
with phishing websites.
</div>

<div class="advice-box">

<div class="advice-title">
What should you do?
</div>

• Do not enter passwords or personal information.<br>
• Do not provide payment or banking details.<br>
• Verify the website address before continuing.<br>
• If you received this link unexpectedly, avoid opening it.

</div>

</div>
""",
            unsafe_allow_html=True,
        )


    else:

        st.markdown(
            """
<div class="safe-card">

<div class="result-icon">✅</div>

<div class="result-title">
No Strong Phishing Signs Detected
</div>

<div class="result-message">
The link does not show strong characteristics commonly
associated with phishing websites.
</div>

<div class="advice-box">

<div class="advice-title">
Stay cautious
</div>

• Make sure the website address is correct.<br>
• Be careful when entering passwords or payment details.<br>
• Avoid links received from unknown or suspicious sources.

</div>

</div>
""",
            unsafe_allow_html=True,
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
<div class="footer-text">
This tool helps identify suspicious links but cannot guarantee
that every website is safe.
</div>
""",
    unsafe_allow_html=True,
)
