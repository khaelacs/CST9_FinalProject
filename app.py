import streamlit as st
import pandas as pd
import joblib

from urllib.parse import urlparse

from feature_extractor import extract_features


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Phishing Website Detector",
    page_icon="🛡️",
    layout="centered"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

.main {
    background-color: #f8f9fa;
}

.title {
    text-align: center;
    font-size: 42px;
    font-weight: 700;
    margin-bottom: 10px;
}

.subtitle {
    text-align: center;
    font-size: 18px;
    color: #666666;
    margin-bottom: 30px;
}

.result {
    padding: 25px;
    border-radius: 15px;
    text-align: center;
    margin-top: 25px;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# LOAD MODEL
# =========================================================

@st.cache_resource
def load_model():

    model = joblib.load(
        "final_random_forest.pkl"
    )

    selected_features = joblib.load(
        "selected_features.pkl"
    )

    return model, selected_features


model, selected_features = load_model()


# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="title">🛡️ Phishing Website Detector</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Enter a website URL to check whether it is '
    'legitimate or phishing.'
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# URL INPUT
# =========================================================

url = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)


# =========================================================
# CHECK BUTTON
# =========================================================

if st.button(
    "🔍 Check Website",
    use_container_width=True
):

    if not url.strip():

        st.warning(
            "Please enter a website URL."
        )

    else:

        # Add HTTPS if missing
        if not url.startswith(
            ("http://", "https://")
        ):

            url = "https://" + url

        parsed = urlparse(url)

        if not parsed.netloc:

            st.error(
                "Please enter a valid website URL."
            )

        else:

            with st.spinner(
                "Analyzing website..."
            ):

                try:

                    # -------------------------------------
                    # EXTRACT FEATURES
                    # -------------------------------------

                    features = extract_features(
                        url
                    )

                    # -------------------------------------
                    # CREATE DATAFRAME
                    # -------------------------------------

                    input_data = pd.DataFrame(
                        [features]
                    )

                    # -------------------------------------
                    # CHECK REQUIRED FEATURES
                    # -------------------------------------

                    missing_features = [
                        feature
                        for feature in selected_features
                        if feature not in input_data.columns
                    ]

                    if missing_features:

                        st.error(
                            "Missing features: "
                            + ", ".join(
                                missing_features
                            )
                        )

                        st.stop()

                    # -------------------------------------
                    # ORDER FEATURES EXACTLY
                    # LIKE TRAINING
                    # -------------------------------------

                    input_data = input_data[
                        selected_features
                    ]

                    # -------------------------------------
                    # PREDICTION
                    # -------------------------------------

                    prediction = model.predict(
                        input_data
                    )[0]

                    probability = model.predict_proba(
                        input_data
                    )[0]

                    legitimate_probability = (
                        probability[0] * 100
                    )

                    phishing_probability = (
                        probability[1] * 100
                    )

                    # -------------------------------------
                    # RESULT
                    # -------------------------------------

                    if prediction == 1:

                        st.error(
                            "⚠️ PHISHING WEBSITE"
                        )

                        st.write(
                            f"Phishing probability: "
                            f"**{phishing_probability:.2f}%**"
                        )

                    else:

                        st.success(
                            "✅ LEGITIMATE WEBSITE"
                        )

                        st.write(
                            f"Legitimate probability: "
                            f"**{legitimate_probability:.2f}%**"
                        )

                    # -------------------------------------
                    # DETAILS
                    # -------------------------------------

                    with st.expander(
                        "View Analysis Details"
                    ):

                        st.write(
                            "URL analyzed:"
                        )

                        st.code(url)

                        st.write(
                            "Features extracted:",
                            len(input_data.columns)
                        )

                except Exception as e:

                    st.error(
                        "Unable to analyze this website."
                    )

                    st.caption(
                        f"Error: {str(e)}"
                    )
