import re
import os
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
import whois
import tldextract

from bs4 import BeautifulSoup
from tranco import Tranco


# ============================================================
# SETTINGS
# ============================================================

TIMEOUT = 10

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0 Safari/537.36"
    )
}


# ============================================================
# EXACT 40 FEATURES USED BY YOUR RANDOM FOREST
# ============================================================

SELECTED_FEATURES = [
    "google_index",
    "page_rank",
    "nb_hyperlinks",
    "web_traffic",
    "nb_www",
    "domain_age",
    "ratio_extHyperlinks",
    "safe_anchor",
    "length_url",
    "ratio_intHyperlinks",
    "longest_words_raw",
    "phish_hints",
    "length_hostname",
    "char_repeat",
    "domain_in_title",
    "shortest_word_path",
    "ratio_extRedirection",
    "domain_registration_length",
    "ratio_digits_host",
    "nb_slash",
    "nb_dots",
    "shortest_word_host",
    "ip",
    "nb_hyphens",
    "shortest_words_raw",
    "longest_word_host",
    "nb_qm",
    "domain_with_copyright",
    "ratio_extMedia",
    "ratio_extErrors",
    "ratio_intMedia",
    "nb_extCSS",
    "nb_subdomains",
    "nb_redirection",
    "domain_in_brand",
    "nb_and",
    "nb_underscore",
    "https_token",
    "external_favicon",
    "empty_title"
]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def get_url_information(url):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    hostname = hostname.lower()

    extracted = tldextract.extract(url)

    domain = extracted.domain or ""

    suffix = extracted.suffix or ""

    subdomain = extracted.subdomain or ""

    if domain and suffix:
        registered_domain = domain + "." + suffix
    else:
        registered_domain = hostname

    return (
        parsed,
        hostname,
        registered_domain,
        domain,
        subdomain
    )


def split_words(text):

    if not text:
        return []

    words = re.split(
        r"[^a-zA-Z0-9]+",
        text.lower()
    )

    return [
        word
        for word in words
        if word
    ]


def is_internal_url(resource_url, hostname):

    try:

        resource_host = (
            urlparse(resource_url).hostname
            or ""
        ).lower()

        hostname = hostname.lower()

        if not resource_host:
            return True

        return (
            resource_host == hostname
            or resource_host.endswith("." + hostname)
        )

    except Exception:

        return True


# ============================================================
# 1. URL FEATURES
# ============================================================

def extract_url_features(url):

    (
        parsed,
        hostname,
        registered_domain,
        domain,
        subdomain
    ) = get_url_information(url)

    path = parsed.path or ""

    query = parsed.query or ""

    url_lower = url.lower()

    hostname_lower = hostname.lower()

    # --------------------------------------------------------
    # URL WORDS
    # --------------------------------------------------------

    raw_words = (
        split_words(domain)
        + split_words(subdomain)
        + split_words(path)
        + split_words(query)
    )

    host_words = (
        split_words(domain)
        + split_words(subdomain)
    )

    path_words = split_words(path)

    # --------------------------------------------------------
    # WORD LENGTHS
    # --------------------------------------------------------

    raw_lengths = [
        len(word)
        for word in raw_words
    ]

    host_lengths = [
        len(word)
        for word in host_words
    ]

    path_lengths = [
        len(word)
        for word in path_words
    ]

    shortest_words_raw = (
        min(raw_lengths)
        if raw_lengths
        else 0
    )

    longest_words_raw = (
        max(raw_lengths)
        if raw_lengths
        else 0
    )

    shortest_word_host = (
        min(host_lengths)
        if host_lengths
        else 0
    )

    longest_word_host = (
        max(host_lengths)
        if host_lengths
        else 0
    )

    shortest_word_path = (
        min(path_lengths)
        if path_lengths
        else 0
    )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    ip = 0

    try:
        ipaddress.ip_address(hostname)
        ip = 1

    except ValueError:
        ip = 0

    # --------------------------------------------------------
    # DIGIT RATIO IN HOST
    # --------------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    if len(hostname) > 0:

        ratio_digits_host = (
            digit_count / len(hostname)
        )

    else:

        ratio_digits_host = 0

    # --------------------------------------------------------
    # NUMBER OF SUBDOMAINS
    # --------------------------------------------------------

    if subdomain:

        nb_subdomains = len(
            subdomain.split(".")
        )

    else:

        nb_subdomains = 0

    # --------------------------------------------------------
    # CHARACTER REPETITION
    # --------------------------------------------------------

    char_repeat = 0

    for word in raw_words:

        for i in range(
            len(word) - 1
        ):

            if word[i] == word[i + 1]:

                char_repeat += 1

    # --------------------------------------------------------
    # PHISHING HINTS
    # --------------------------------------------------------
    #
    # IMPORTANT:
    # This does NOT classify the website.
    #
    # It only calculates a numerical feature.
    # The Random Forest makes the final decision.
    #
    # --------------------------------------------------------

    # Match the public dataset's documented phishing-hint vocabulary.
    phishing_terms = [
        "wp", "login", "includes", "content", "site", "admin",
        "images", "js", "alibaba", "css", "myaccount", "dropbox",
        "themes", "plugins", "signin", "view"
    ]

    # Count occurrences, not just unique matched terms.
    phish_hints = sum(
        url_lower.count(term)
        for term in phishing_terms
    )

    # --------------------------------------------------------
    # DOMAIN IN BRAND
    # --------------------------------------------------------
    #
    # Again, this ONLY creates a feature.
    # It does NOT say phishing.
    #
    # --------------------------------------------------------

    brands = [
        "google",
        "facebook",
        "instagram",
        "youtube",
        "twitter",
        "microsoft",
        "apple",
        "amazon",
        "paypal",
        "linkedin",
        "netflix",
        "spotify",
        "github",
        "outlook",
        "gmail",
        "yahoo",
        "ebay",
        "reddit",
        "tiktok",
        "whatsapp",
        "telegram",
        "discord",
        "dropbox",
        "adobe",
        "canva",
        "wordpress",
        "shopify",
        "binance",
        "coinbase"
    ]

    domain_in_brand = 0

    for brand in brands:

        if brand in domain.lower():

            domain_in_brand = 1
            break

    # --------------------------------------------------------
    # RETURN URL FEATURES
    # --------------------------------------------------------

    return {

        "nb_www":
            url_lower.count("www"),

        "length_url":
            len(url),

        "longest_words_raw":
            longest_words_raw,

        "phish_hints":
            phish_hints,

        "length_hostname":
            len(hostname),

        "char_repeat":
            char_repeat,

        "shortest_word_path":
            shortest_word_path,

        "ratio_digits_host":
            ratio_digits_host,

        "nb_slash":
            url.count("/"),

        "nb_dots":
            url.count("."),

        "shortest_word_host":
            shortest_word_host,

        "ip":
            ip,

        "nb_hyphens":
            url.count("-"),

        "shortest_words_raw":
            shortest_words_raw,

        "longest_word_host":
            longest_word_host,

        "nb_qm":
            url.count("?"),

        "domain_in_brand":
            domain_in_brand,

        "nb_and":
            url.count("&"),

        "nb_underscore":
            url.count("_"),

        "https_token":
            1 if parsed.scheme.lower() == "https" else 0,

        "nb_subdomains":
            nb_subdomains
    }


# ============================================================
# 2. DOWNLOAD THE WEBPAGE
# ============================================================

def get_webpage(url):

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        return response

    except Exception as error:

        print(
            "Unable to access webpage:",
            error
        )

        return None


# ============================================================
# 3. WEBPAGE / HTML FEATURES
# ============================================================

def extract_webpage_features(
    url,
    response
):

    (
        parsed,
        hostname,
        registered_domain,
        domain,
        subdomain
    ) = get_url_information(url)

    # Default values
    features = {

        "nb_hyperlinks": 0,

        "ratio_extHyperlinks": 0,

        "safe_anchor": 0,

        "ratio_intHyperlinks": 0,

        "domain_in_title": 0,

        "ratio_extRedirection": 0,

        "domain_with_copyright": 0,

        "ratio_extMedia": 0,

        "ratio_extErrors": 0,

        "ratio_intMedia": 0,

        "nb_extCSS": 0,

        "nb_redirection": 0,

        "external_favicon": 0,

        "empty_title": 1
    }

    if response is None:

        return features

    try:

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

    except Exception:

        return features

    # ========================================================
    # REDIRECTS
    # ========================================================

    features[
        "nb_redirection"
    ] = len(
        response.history
    )

    # ========================================================
    # HYPERLINKS
    # ========================================================

    anchors = soup.find_all(
        "a",
        href=True
    )

    total_links = len(anchors)

    internal_links = 0
    external_links = 0

    safe_links = 0

    for anchor in anchors:

        href = (
            anchor.get("href")
            or ""
        ).strip()

        if not href:
            continue

        # Safe usable links
        if not href.startswith(
            (
                "#",
                "javascript:",
                "mailto:"
            )
        ):

            safe_links += 1

        full_url = urljoin(
            url,
            href
        )

        if is_internal_url(
            full_url,
            hostname
        ):

            internal_links += 1

        else:

            external_links += 1

    features[
        "nb_hyperlinks"
    ] = total_links

    if total_links > 0:

        features[
            "ratio_intHyperlinks"
        ] = (
            internal_links
            / total_links
        )

        features[
            "ratio_extHyperlinks"
        ] = (
            external_links
            / total_links
        )

        # The training dataset stores safe_anchor on a 0-100 scale.
        features[
            "safe_anchor"
        ] = (
            safe_links
            / total_links
        ) * 100

    # ========================================================
    # TITLE
    # ========================================================

    title_tag = soup.find("title")

    if title_tag:

        title = title_tag.get_text(
            " ",
            strip=True
        )

    else:

        title = ""

    if title:

        features[
            "empty_title"
        ] = 0

        if domain.lower() in title.lower():

            features[
                "domain_in_title"
            ] = 1

    else:

        features[
            "empty_title"
        ] = 1

    # ========================================================
    # COPYRIGHT
    # ========================================================

    page_text = soup.get_text(
        " ",
        strip=True
    )

    page_text_lower = (
        page_text.lower()
    )

    copyright_position = (
        page_text_lower.find(
            "copyright"
        )
    )

    if copyright_position >= 0:

        nearby_text = page_text_lower[
            copyright_position:
            copyright_position + 500
        ]

        if domain.lower() in nearby_text:

            features[
                "domain_with_copyright"
            ] = 1

    # ========================================================
    # MEDIA
    # ========================================================

    media_tags = []

    media_tags.extend(
        soup.find_all(
            "img",
            src=True
        )
    )

    media_tags.extend(
        soup.find_all(
            "audio",
            src=True
        )
    )

    media_tags.extend(
        soup.find_all(
            "video",
            src=True
        )
    )

    media_tags.extend(
        soup.find_all(
            "source",
            src=True
        )
    )

    internal_media = 0
    external_media = 0

    for tag in media_tags:

        source = tag.get(
            "src"
        )

        if not source:
            continue

        media_url = urljoin(
            url,
            source
        )

        if is_internal_url(
            media_url,
            hostname
        ):

            internal_media += 1

        else:

            external_media += 1

    total_media = (
        internal_media
        + external_media
    )

    if total_media > 0:

        # The training dataset stores media ratios on a 0-100 scale.
        features[
            "ratio_intMedia"
        ] = (
            internal_media
            / total_media
        ) * 100

        features[
            "ratio_extMedia"
        ] = (
            external_media
            / total_media
        ) * 100

    # ========================================================
    # EXTERNAL CSS
    # ========================================================

    css_links = soup.find_all(
        "link",
        href=True
    )

    external_css = 0

    for link in css_links:

        rel = link.get(
            "rel",
            []
        )

        rel = [
            str(value).lower()
            for value in rel
        ]

        if "stylesheet" not in rel:

            continue

        css_url = urljoin(
            url,
            link.get("href")
        )

        if not is_internal_url(
            css_url,
            hostname
        ):

            external_css += 1

    features[
        "nb_extCSS"
    ] = external_css

    # ========================================================
    # FAVICON
    # ========================================================

    icon_links = soup.find_all(
        "link",
        href=True
    )

    for link in icon_links:

        rel = link.get(
            "rel",
            []
        )

        rel_text = " ".join(
            str(value).lower()
            for value in rel
        )

        if "icon" in rel_text:

            favicon_url = urljoin(
                url,
                link.get("href")
            )

            if not is_internal_url(
                favicon_url,
                hostname
            ):

                features[
                    "external_favicon"
                ] = 1

            break

    # ========================================================
    # EXTERNAL REDIRECTION
    # ========================================================

    external_redirects = 0

    for redirect in response.history:

        redirect_host = (
            urlparse(
                redirect.url
            ).hostname
            or ""
        ).lower()

        if (
            redirect_host
            and redirect_host != hostname
        ):

            external_redirects += 1

    if len(response.history) > 0:

        features[
            "ratio_extRedirection"
        ] = (
            external_redirects
            / len(response.history)
        )

    # ========================================================
    # EXTERNAL LINK ERRORS
    # ========================================================

    external_urls = []

    for anchor in anchors:

        href = anchor.get(
            "href"
        )

        if not href:
            continue

        full_url = urljoin(
            url,
            href
        )

        if not is_internal_url(
            full_url,
            hostname
        ):

            external_urls.append(
                full_url
            )

    # Check only a few URLs so the
    # application does not become too slow.

    check_urls = external_urls[:5]

    error_count = 0

    for external_url in check_urls:

        try:

            result = requests.head(
                external_url,
                headers=HEADERS,
                timeout=3,
                allow_redirects=True
            )

            if result.status_code >= 400:

                error_count += 1

        except Exception:

            error_count += 1

    if check_urls:

        features[
            "ratio_extErrors"
        ] = (
            error_count
            / len(check_urls)
        )

    return features


# ============================================================
# 4. WHOIS FEATURES
# ============================================================
#
# These two are automatically obtained from the domain.
# They are NOT classification rules.
#
# ============================================================

def get_date(value):

    if value is None:
        return None

    if isinstance(value, list):

        values = [
            item
            for item in value
            if isinstance(
                item,
                datetime
            )
        ]

        if not values:
            return None

        value = values[0]

    if not isinstance(
        value,
        datetime
    ):

        return None

    if value.tzinfo is None:

        value = value.replace(
            tzinfo=timezone.utc
        )

    return value


def extract_whois_features(
    registered_domain
):

    domain_age = -1

    domain_registration_length = -1

    try:

        information = whois.whois(
            registered_domain
        )

        creation_date = get_date(
            information.creation_date
        )

        expiration_date = get_date(
            information.expiration_date
        )

        now = datetime.now(
            timezone.utc
        )

        # Domain age
        if creation_date:

            domain_age = max(
                0,
                (
                    now - creation_date
                ).days
            )

        # Registration length
        if (
            creation_date
            and expiration_date
        ):

            domain_registration_length = max(
                0,
                (
                    expiration_date
                    - creation_date
                ).days
            )

    except Exception as error:

        print(
            "WHOIS unavailable:",
            error
        )

    return {
        "domain_age":
            domain_age,

        "domain_registration_length":
            domain_registration_length
    }


# ============================================================
# 5. EXTERNAL FEATURE #1
# GOOGLE INDEX
# ============================================================

def get_secret(name):

    # Streamlit Cloud
    try:

        import streamlit as st

        value = st.secrets.get(
            name,
            None
        )

        if value:
            return value

    except Exception:
        pass

    # Local environment
    return os.getenv(name)


def extract_google_index(
    registered_domain
):

    api_key = get_secret(
        "SERPER_API_KEY"
    )

    if not api_key:

        raise RuntimeError(
            "SERPER_API_KEY is not configured."
        )

    response = requests.post(
        "https://google.serper.dev/search",

        headers={
            "X-API-KEY": api_key,
            "Content-Type":
                "application/json"
        },

        json={
            "q":
                f"site:{registered_domain}",
            "num": 1
        },

        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    results = data.get(
        "organic",
        []
    )

    # IMPORTANT:
    # This only creates the google_index feature.
    # It does not classify the URL.

    if len(results) > 0:

        return 1

    return 0


# ============================================================
# 6. EXTERNAL FEATURE #2
# PAGE RANK
# ============================================================

def extract_page_rank(
    registered_domain
):

    api_key = get_secret(
        "OPENPAGERANK_API_KEY"
    )

    if not api_key:

        raise RuntimeError(
            "OPENPAGERANK_API_KEY is not configured."
        )

    response = requests.post(

        "https://openpagerank.keywordseverywhere.com"
        "/v1/domains/bulk",

        headers={
            "Authorization":
                f"Bearer {api_key}",

            "Content-Type":
                "application/json"
        },

        json={
            "domains": [
                registered_domain
            ],

            "include_history": False
        },

        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    results = data.get(
        "results",
        []
    )

    if not results:

        return 0

    result = results[0]

    if not result.get(
        "found",
        False
    ):

        return 0

    # OpenPageRank gives a 0–10 score.
    #
    # Your training dataset uses page_rank
    # as a 0–10 feature.
    #
    # We round to an integer so the live
    # feature has the same general scale.

    page_rank = result.get(
        "open_page_rank",
        0
    )

    if page_rank is None:

        return 0

    return round(
        float(page_rank)
    )


# ============================================================
# 7. EXTERNAL FEATURE #3
# WEB TRAFFIC
# ============================================================

def extract_web_traffic(
    registered_domain
):

    try:

        tranco = Tranco(
            cache=True,
            cache_dir=".tranco"
        )

        latest_list = tranco.list()

        rank = latest_list.rank(
            registered_domain
        )

        # Tranco returns -1 when the
        # domain is not found.

        if rank == -1:

            return 0

        return int(rank)

    except Exception as error:

        print(
            "Tranco error:",
            error
        )

        return 0


# ============================================================
# 8. MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    # --------------------------------------------------------
    # STEP 1
    # Normalize URL
    # --------------------------------------------------------

    url = normalize_url(url)

    print(
        "Extracting features from:",
        url
    )

    # --------------------------------------------------------
    # STEP 2
    # Extract URL-based features
    # --------------------------------------------------------

    features = extract_url_features(
        url
    )

    # --------------------------------------------------------
    # STEP 3
    # Get domain information
    # --------------------------------------------------------

    (
        parsed,
        hostname,
        registered_domain,
        domain,
        subdomain
    ) = get_url_information(url)

    # --------------------------------------------------------
    # STEP 4
    # Download webpage
    # --------------------------------------------------------

    response = get_webpage(
        url
    )

    # --------------------------------------------------------
    # STEP 5
    # Extract HTML/webpage features
    # --------------------------------------------------------

    webpage_features = (
        extract_webpage_features(
            url,
            response
        )
    )

    features.update(
        webpage_features
    )

    # --------------------------------------------------------
    # STEP 6
    # WHOIS
    # --------------------------------------------------------

    whois_features = (
        extract_whois_features(
            registered_domain
        )
    )

    features.update(
        whois_features
    )

    # --------------------------------------------------------
    # STEP 7
    # THREE LIVE EXTERNAL FEATURES
    # --------------------------------------------------------

    features[
        "google_index"
    ] = extract_google_index(
        registered_domain
    )

    features[
        "page_rank"
    ] = extract_page_rank(
        registered_domain
    )

    features[
        "web_traffic"
    ] = extract_web_traffic(
        registered_domain
    )

    # --------------------------------------------------------
    # STEP 8
    # CHECK THAT ALL 40 FEATURES EXIST
    # --------------------------------------------------------

    missing = [
        feature
        for feature in SELECTED_FEATURES
        if feature not in features
    ]

    if missing:

        raise ValueError(
            "Missing features: "
            + str(missing)
        )

    # --------------------------------------------------------
    # STEP 9
    # RETURN EXACTLY THE 40 FEATURES
    # --------------------------------------------------------

    final_features = {
        feature: features[feature]
        for feature in SELECTED_FEATURES
    }

    # Final sanity check: the Random Forest expects numeric values.
    for feature, value in final_features.items():
        if value is None:
            raise ValueError(f"Feature '{feature}' is None.")
        try:
            final_features[feature] = float(value)
        except (TypeError, ValueError):
            raise ValueError(
                f"Feature '{feature}' is not numeric: {value!r}"
            )

    print(
        "Total features extracted:",
        len(final_features)
    )

    return final_features
