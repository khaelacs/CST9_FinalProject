import re
import os
import ipaddress
from urllib.parse import urlparse, urljoin

import requests
import tldextract
from bs4 import BeautifulSoup


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
# EXACT 40 FEATURES USED BY RANDOM FOREST
# ============================================================

SELECTED_FEATURES = [
    "nb_hyperlinks",
    "nb_www",
    "phish_hints",
    "ratio_extHyperlinks",
    "ratio_intHyperlinks",
    "longest_words_raw",
    "safe_anchor",
    "length_url",
    "length_hostname",
    "ratio_extRedirection",
    "char_repeat",
    "nb_dots",
    "nb_slash",
    "shortest_word_host",
    "ratio_digits_host",
    "shortest_word_path",
    "domain_with_copyright",
    "domain_in_title",
    "ip",
    "longest_word_host",
    "nb_hyphens",
    "shortest_words_raw",
    "ratio_intMedia",
    "ratio_extErrors",
    "domain_in_brand",
    "nb_qm",
    "ratio_extMedia",
    "nb_subdomains",
    "nb_extCSS",
    "nb_redirection",
    "nb_underscore",
    "empty_title",
    "prefix_suffix",
    "https_token",
    "external_favicon",
    "shortening_service",
    "random_domain",
    "login_form",
    "nb_com",
    "tld_in_subdomain"
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
        subdomain,
        suffix
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
        subdomain,
        suffix
    ) = get_url_information(url)

    path = parsed.path or ""
    query = parsed.query or ""

    url_lower = url.lower()
    hostname_lower = hostname.lower()

    # --------------------------------------------------------
    # WORDS
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

    if hostname:

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
        ) + 1

    else:

        nb_subdomains = 1

    # --------------------------------------------------------
    # CHARACTER REPETITION
    # --------------------------------------------------------

    char_repeat = 0

    for word in raw_words:

        for i in range(len(word) - 1):

            if word[i] == word[i + 1]:

                char_repeat += 1

    # --------------------------------------------------------
    # PHISHING HINTS
    # --------------------------------------------------------

    phishing_terms = [
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "confirm",
        "banking",
        "wallet",
        "authenticate"
    ]

    phish_hints = 0

    for term in phishing_terms:

        if term in url_lower:

            phish_hints += 1

    # --------------------------------------------------------
    # DOMAIN IN BRAND
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
    # PREFIX / SUFFIX
    # --------------------------------------------------------

    prefix_suffix = 0

    if "-" in domain:

        prefix_suffix = 1

    # --------------------------------------------------------
    # HTTPS TOKEN
    # --------------------------------------------------------

    https_token = (
        1
        if parsed.scheme.lower() == "https"
        else 0
    )

    # --------------------------------------------------------
    # URL SHORTENING SERVICE
    # --------------------------------------------------------

    shortening_services = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bit.do",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "lnkd.in",
        "rebrand.ly",
        "trib.al"
    ]

    shortening_service = 0

    for service in shortening_services:

        if hostname == service or hostname.endswith(
            "." + service
        ):

            shortening_service = 1
            break

    # --------------------------------------------------------
    # RANDOM DOMAIN
    # --------------------------------------------------------
    #
    # Reconstructed approximation.
    # This checks for a domain containing a high
    # proportion of random-looking characters.
    #
    # --------------------------------------------------------

    random_domain = 0

    if domain:

        letters = re.findall(
            r"[a-z]",
            domain.lower()
        )

        if len(letters) >= 6:

            vowel_count = sum(
                char in "aeiou"
                for char in letters
            )

            vowel_ratio = (
                vowel_count / len(letters)
            )

            if vowel_ratio < 0.15:

                random_domain = 1

    # --------------------------------------------------------
    # NUMBER OF ".COM"
    # --------------------------------------------------------

    nb_com = url_lower.count(".com")

    # --------------------------------------------------------
    # TLD IN SUBDOMAIN
    # --------------------------------------------------------

    tld_in_subdomain = 0

    if subdomain and suffix:

        suffix_parts = suffix.lower().split(".")

        subdomain_lower = subdomain.lower()

        for tld_part in suffix_parts:

            if tld_part in subdomain_lower.split("."):

                tld_in_subdomain = 1
                break

    # --------------------------------------------------------
    # RETURN
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

        "nb_underscore":
            url.count("_"),

        "https_token":
            https_token,

        "nb_subdomains":
            nb_subdomains,

        "prefix_suffix":
            prefix_suffix,

        "shortening_service":
            shortening_service,

        "random_domain":
            random_domain,

        "nb_com":
            nb_com,

        "tld_in_subdomain":
            tld_in_subdomain
    }


# ============================================================
# 2. DOWNLOAD WEBPAGE
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
        subdomain,
        suffix
    ) = get_url_information(url)

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

        "empty_title": 1,

        "login_form": 0
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
    # REDIRECTION
    # ========================================================

    features["nb_redirection"] = len(
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

    external_urls = []

    for anchor in anchors:

        href = (
            anchor.get("href")
            or ""
        ).strip()

        if not href:
            continue

        full_url = urljoin(
            url,
            href
        )

        # ----------------------------------------------------
        # SAFE ANCHOR
        # ----------------------------------------------------

        if href not in [
            "#",
            "",
            "javascript:void(0)",
            "javascript:void(0);"
        ]:

            safe_links += 1

        # ----------------------------------------------------
        # INTERNAL / EXTERNAL
        # ----------------------------------------------------

        if is_internal_url(
            full_url,
            hostname
        ):

            internal_links += 1

        else:

            external_links += 1

            external_urls.append(
                full_url
            )

    features["nb_hyperlinks"] = total_links

    if total_links > 0:

        features["ratio_intHyperlinks"] = (
            internal_links / total_links
        )

        features["ratio_extHyperlinks"] = (
            external_links / total_links
        )

        # Dataset uses percentage scale.
        features["safe_anchor"] = (
            safe_links / total_links
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

        features["empty_title"] = 0

        if domain.lower() in title.lower():

            features["domain_in_title"] = 1

    else:

        features["empty_title"] = 1

    # ========================================================
    # COPYRIGHT
    # ========================================================

    page_text = soup.get_text(
        " ",
        strip=True
    )

    page_text_lower = page_text.lower()

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

        source = tag.get("src")

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

        # Dataset uses percentage scale.
        features["ratio_intMedia"] = (
            internal_media / total_media
        ) * 100

        features["ratio_extMedia"] = (
            external_media / total_media
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

    features["nb_extCSS"] = external_css

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

        if redirect_host:

            if not is_internal_url(
                redirect.url,
                hostname
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

    error_count = 0

    for external_url in external_urls:

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

    if external_urls:

        features[
            "ratio_extErrors"
        ] = (
            error_count
            / len(external_urls)
        )

    # ========================================================
    # LOGIN FORM
    # ========================================================

    forms = soup.find_all("form")

    for form in forms:

        form_text = (
            form.get_text(
                " ",
                strip=True
            ).lower()
        )

        form_html = str(
            form
        ).lower()

        login_keywords = [
            "login",
            "log in",
            "signin",
            "sign in",
            "password",
            "username",
            "email"
        ]

        found_keyword = any(
            keyword in form_text
            or keyword in form_html
            for keyword in login_keywords
        )

        password_input = form.find(
            "input",
            {
                "type": "password"
            }
        )

        if found_keyword or password_input:

            features["login_form"] = 1
            break

    return features


# ============================================================
# 4. MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    # --------------------------------------------------------
    # STEP 1: Normalize URL
    # --------------------------------------------------------

    url = normalize_url(url)

    print(
        "Extracting features from:",
        url
    )

    # --------------------------------------------------------
    # STEP 2: URL FEATURES
    # --------------------------------------------------------

    features = extract_url_features(
        url
    )

    # --------------------------------------------------------
    # STEP 3: WEBPAGE
    # --------------------------------------------------------

    response = get_webpage(
        url
    )

    # --------------------------------------------------------
    # STEP 4: HTML FEATURES
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
    # STEP 5: CHECK ALL 40 FEATURES
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
    # STEP 6: RETURN EXACTLY 40 FEATURES
    # --------------------------------------------------------

    final_features = {
        feature: features[feature]
        for feature in SELECTED_FEATURES
    }

    print(
        "Total features extracted:",
        len(final_features)
    )

    return final_features
