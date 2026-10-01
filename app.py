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
# 1. FILE LOCATIONS
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
# 2. PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Phishing Website Detector",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# 3. CUSTOM DESIGN
# ============================================================

st.markdown(
    """
    <style>

    .block-container {
        max-width: 850px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    .main-title {
        text-align: center;
        font-size: 42px;
        font-weight: 800;
        margin-bottom: 5px;
    }

    .subtitle {
        text-align: center;
        color: #777;
        font-size: 17px;
        margin-bottom: 30px;
    }

    .result-safe {
        background-color: rgba(40, 167, 69, 0.10);
        border: 2px solid #28a745;
        padding: 25px;
        border-radius: 14px;
        text-align: center;
        margin-top: 20px;
    }

    .result-danger {
        background-color: rgba(220, 53, 69, 0.10);
        border: 2px solid #dc3545;
        padding: 25px;
        border-radius: 14px;
        text-align: center;
        margin-top: 20px;
    }

    .result-title {
        font-size: 28px;
        font-weight: 800;
    }

    .small-text {
        color: #777;
        font-size: 14px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# 4. LOAD MACHINE LEARNING FILES
# ============================================================

@st.cache_resource
def load_system():

    if not os.path.exists(MODEL_FILE):

        raise FileNotFoundError(
            "final_random_forest.pkl was not found."
        )

    if not os.path.exists(FEATURE_FILE):

        raise FileNotFoundError(
            "selected_features.pkl was not found."
        )

    if not os.path.exists(THRESHOLD_FILE):

        raise FileNotFoundError(
            "phishing_threshold.pkl was not found."
        )


    model = joblib.load(
        MODEL_FILE
    )

    selected_features = joblib.load(
        FEATURE_FILE
    )

    threshold = joblib.load(
        THRESHOLD_FILE
    )


    return (
        model,
        selected_features,
        float(threshold)
    )


try:

    (
        model,
        selected_features,
        threshold
    ) = load_system()

except Exception as error:

    st.error(
        "Unable to load the machine learning files."
    )

    st.code(
        str(error)
    )

    st.stop()


# ============================================================
# 5. VERIFY MODEL FEATURES
# ============================================================

selected_features = list(
    selected_features
)


missing_in_extractor = [
    feature
    for feature in selected_features
    if feature not in SELECTED_FEATURES
]

if missing_in_extractor:

    st.error(
        "The trained model contains features "
        "that the feature extractor does not support."
    )

    st.write(
        missing_in_extractor
    )

    st.stop()


extra_in_extractor = [
    feature
    for feature in SELECTED_FEATURES
    if feature not in selected_features
]

if extra_in_extractor:

    st.warning(
        "The feature extractor and saved feature list "
        "are not exactly the same."
    )


if hasattr(
    model,
    "n_features_in_"
):

    if model.n_features_in_ != len(
        selected_features
    ):

        st.error(
            "The Random Forest model and "
            "selected_features.pkl do not match."
        )

        st.stop()


# ============================================================
# 6. CACHE FEATURE EXTRACTION
# ============================================================

@st.cache_data(
    ttl=300,
    show_spinner=False
)
def extract_cached(
    url
):

    return extract_features(
        url
    )


# ============================================================
# 7. HEADER
# ============================================================

st.markdown(
    """
    <div class="main-title">
        🛡️ Phishing Website Detector
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="subtitle">
        Machine Learning-Based URL and Website Analysis
    </div>
    """,
    unsafe_allow_html=True
)

st.write(
    """
    Enter a website URL below. The system extracts the same
    features used during training and sends them to the trained
    Random Forest model.
    """
)


# ============================================================
# 8. URL INPUT
# ============================================================

url_input = st.text_input(
    "Website URL",
    placeholder="https://www.example.com"
)


# ============================================================
# 9. ANALYZE BUTTON
# ============================================================

analyze_button = st.button(
    "🔍 Analyze Website",
    type="primary",
    use_container_width=True
)


# ============================================================
# 10. ANALYSIS
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

    except FeatureExtractionError as error:

        st.error(
            str(error)
        )

        st.stop()


    start_time = time.perf_counter()


    with st.spinner(
        "Downloading webpage and extracting features..."
    ):

        try:

            features = extract_cached(
                normalized_url
            )

        except FeatureExtractionError as error:

            st.error(
                "Unable to analyze this website."
            )

            st.warning(
                str(error)
            )

            st.stop()

        except Exception as error:

            st.error(
                "An unexpected error occurred "
                "during feature extraction."
            )

            st.code(
                str(error)
            )

            st.stop()


    # ========================================================
    # 11. CREATE MODEL INPUT
    # ========================================================

    input_data = pd.DataFrame(
        [features]
    )


    missing_features = [
        feature
        for feature in selected_features
        if feature not in input_data.columns
    ]


    if missing_features:

        st.error(
            "Some machine learning features "
            "could not be extracted."
        )

        st.write(
            missing_features
        )

        st.stop()


    # Exact same feature order used during training
    input_data = input_data[
        selected_features
    ]


    # Ensure everything is numeric
    input_data = input_data.apply(
        pd.to_numeric,
        errors="coerce"
    )


    if input_data.isnull().any().any():

        st.error(
            "One or more extracted features "
            "are not valid numeric values."
        )

        st.stop()


    # ========================================================
    # 12. MACHINE LEARNING PREDICTION
    # ========================================================

    try:

        probabilities = model.predict_proba(
            input_data
        )[0]

    except Exception as error:

        st.error(
            "The Random Forest model could not "
            "process the extracted features."
        )

        st.code(
            str(error)
        )

        st.stop()


    # ========================================================
    # 13. FIND PHISHING CLASS
    # ========================================================

    classes = list(
        model.classes_
    )


    if 1 not in classes:

        st.error(
            "The trained model does not contain "
            "class 1 for phishing."
        )

        st.stop()


    phishing_index = classes.index(
        1
    )


    phishing_probability = float(
        probabilities[
            phishing_index
        ]
    )


    legitimate_probability = (
        1.0
        - phishing_probability
    )


    # ========================================================
    # 14. APPLY SAVED VALIDATION THRESHOLD
    # ========================================================

    prediction = (
        1
        if phishing_probability >= threshold
        else 0
    )


    elapsed_time = (
        time.perf_counter()
        - start_time
    )


    # ========================================================
    # 15. DISPLAY RESULT
    # ========================================================

    if prediction == 1:

        st.markdown(
            """
            <div class="result-danger">
                <div class="result-title">
                    ⚠️ PHISHING WEBSITE
                </div>
                <br>
                The Random Forest model classified
                this website as phishing.
            </div>
            """,
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            """
            <div class="result-safe">
                <div class="result-title">
                    ✅ LEGITIMATE WEBSITE
                </div>
                <br>
                The Random Forest model classified
                this website as legitimate.
            </div>
            """,
            unsafe_allow_html=True
        )


    st.write("")


    # ========================================================
    # 16. PROBABILITY DISPLAY
    # ========================================================

    col1, col2 = st.columns(
        2
    )


    with col1:

        st.metric(
            "Legitimate Probability",
            f"{legitimate_probability * 100:.2f}%"
        )


    with col2:

        st.metric(
            "Phishing Probability",
            f"{phishing_probability * 100:.2f}%"
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
        f"Phishing decision threshold: {threshold:.2f}"
    )

    st.caption(
        f"Analysis completed in {elapsed_time:.2f} seconds."
    )


    # ========================================================
    # 17. ANALYSIS DETAILS
    # ========================================================

    with st.expander(
        "🔎 View Analysis Details"
    ):

        st.write(
            "**Analyzed URL:**"
        )

        st.code(
            normalized_url
        )


        st.write(
            "**Machine Learning Model:** "
            "Random Forest"
        )


        st.write(
            "**Features used:**",
            len(
                selected_features
            )
        )


        st.write(
            "**Decision threshold:**",
            threshold
        )


        details = pd.DataFrame({
            "Feature":
                selected_features,

            "Value": [
                input_data.iloc[
                    0
                ][feature]
                for feature
                in selected_features
            ]
        })


        st.dataframe(
            details,
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# 18. FOOTER
# ============================================================

st.divider()

st.caption(
    "This application uses a trained Random Forest "
    "machine learning model. Website classification "
    "is based on the model output and its saved "
    "validation threshold."
)
