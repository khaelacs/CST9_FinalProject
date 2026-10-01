import re
import socket
import requests
import whois

from bs4 import BeautifulSoup
from urllib.parse import urlparse


# =========================================================
# BASIC URL FEATURES
# =========================================================

def extract_url_features(url):
    parsed = urlparse(url)

    hostname = parsed.netloc.lower()
    path = parsed.path
    full_url = url.lower()

    # Remove port if present
    hostname_only = hostname.split(":")[0]

    features = {}

    # -----------------------------------------------------
    # URL structure
    # -----------------------------------------------------

    features["length_url"] = len(url)

    features["length_hostname"] = len(hostname_only)

    features["nb_dots"] = hostname_only.count(".")

    features["nb_hyphens"] = hostname_only.count("-")

    features["nb_slash"] = path.count("/")

    features["nb_qm"] = url.count("?")

    features["nb_and"] = url.count("&")

    features["nb_underscore"] = url.count("_")

    features["nb_www"] = hostname_only.count("www")

    # -----------------------------------------------------
    # IP address
    # -----------------------------------------------------

    try:
        socket.inet_aton(hostname_only)
        features["ip"] = 1
    except:
        features["ip"] = 0

    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    features["https_token"] = 1 if parsed.scheme == "https" else 0

    # -----------------------------------------------------
    # Subdomains
    # -----------------------------------------------------

    parts = hostname_only.split(".")

    if len(parts) > 2:
        features["nb_subdomains"] = len(parts) - 2
    else:
        features["nb_subdomains"] = 0

    # -----------------------------------------------------
    # Domain words
    # -----------------------------------------------------

    host_words = re.findall(r"[A-Za-z0-9]+", hostname_only)

    if host_words:
        features["shortest_word_host"] = min(
            len(word) for word in host_words
        )

        features["longest_word_host"] = max(
            len(word) for word in host_words
        )
    else:
        features["shortest_word_host"] = 0
        features["longest_word_host"] = 0

    # -----------------------------------------------------
    # URL/path words
    # -----------------------------------------------------

    raw_words = re.findall(r"[A-Za-z0-9]+", url)

    if raw_words:
        features["shortest_words_raw"] = min(
            len(word) for word in raw_words
        )

        features["longest_words_raw"] = max(
            len(word) for word in raw_words
        )
    else:
        features["shortest_words_raw"] = 0
        features["longest_words_raw"] = 0

    path_words = re.findall(r"[A-Za-z0-9]+", path)

    if path_words:
        features["shortest_word_path"] = min(
            len(word) for word in path_words
        )
    else:
        features["shortest_word_path"] = 0

    # -----------------------------------------------------
    # Character repetition
    # -----------------------------------------------------

    characters = re.findall(r"[A-Za-z0-9]", url)

    if characters:
        repeated = sum(
            characters[i] == characters[i - 1]
            for i in range(1, len(characters))
        )

        features["char_repeat"] = repeated
    else:
        features["char_repeat"] = 0

    # -----------------------------------------------------
    # Digits in hostname
    # -----------------------------------------------------

    digit_count = sum(char.isdigit() for char in hostname_only)

    if len(hostname_only) > 0:
        features["ratio_digits_host"] = (
            digit_count / len(hostname_only)
        )
    else:
        features["ratio_digits_host"] = 0

    # -----------------------------------------------------
    # Phishing hints
    # -----------------------------------------------------

    phishing_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "bank",
        "password",
        "confirm",
        "authenticate",
        "wallet",
        "payment"
    ]

    features["phish_hints"] = sum(
        word in full_url for word in phishing_words
    )

    # -----------------------------------------------------
    # Domain in brand
    # -----------------------------------------------------

    common_brands = [
        "google",
        "facebook",
        "paypal",
        "microsoft",
        "apple",
        "amazon",
        "instagram",
        "twitter",
        "linkedin",
        "netflix",
        "bank"
    ]

    features["domain_in_brand"] = int(
        any(brand in hostname_only for brand in common_brands)
    )

    return features


# =========================================================
# WEBPAGE FEATURES
# =========================================================

def extract_webpage_features(url):

    features = {}

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent":
                "Mozilla/5.0"
            }
        )

        html = response.text

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

    except Exception:

        # Default values when webpage cannot be accessed
        features["nb_hyperlinks"] = 0
        features["ratio_extHyperlinks"] = 0
        features["safe_anchor"] = 0
        features["ratio_intHyperlinks"] = 0
        features["domain_in_title"] = 0
        features["ratio_extRedirection"] = 0
        features["domain_with_copyright"] = 0
        features["ratio_extMedia"] = 0
        features["ratio_extErrors"] = 0
        features["ratio_intMedia"] = 0
        features["nb_extCSS"] = 0
        features["nb_redirection"] = 0
        features["external_favicon"] = 0
        features["empty_title"] = 1

        return features

    parsed = urlparse(url)

    hostname = parsed.netloc.lower()

    # -----------------------------------------------------
    # TITLE
    # -----------------------------------------------------

    title = soup.title

    if title is None or not title.get_text(strip=True):
        features["empty_title"] = 1
        title_text = ""
    else:
        features["empty_title"] = 0
        title_text = title.get_text(" ", strip=True).lower()

    features["domain_in_title"] = int(
        hostname.replace("www.", "") in title_text
    )

    # -----------------------------------------------------
    # HYPERLINKS
    # -----------------------------------------------------

    links = soup.find_all("a")

    total_links = len(links)

    internal_links = 0
    external_links = 0
    safe_links = 0

    for link in links:

        href = link.get("href")

        if not href:
            continue

        href_lower = href.lower()

        # Safe anchor
        if href_lower in ["#", "javascript:void(0)", "javascript:void(0);"]:
            safe_links += 1

        # External/internal
        if href.startswith("http://") or href.startswith("https://"):

            link_domain = urlparse(href).netloc.lower()

            if hostname in link_domain or link_domain in hostname:
                internal_links += 1
            else:
                external_links += 1

        else:
            internal_links += 1

    features["nb_hyperlinks"] = total_links

    if total_links > 0:

        features["ratio_intHyperlinks"] = (
            internal_links / total_links
        )

        features["ratio_extHyperlinks"] = (
            external_links / total_links
        )

        features["safe_anchor"] = (
            safe_links / total_links
        )

    else:

        features["ratio_intHyperlinks"] = 0
        features["ratio_extHyperlinks"] = 0
        features["safe_anchor"] = 0

    # -----------------------------------------------------
    # REDIRECTION
    # -----------------------------------------------------

    try:
        redirect_count = len(response.history)
    except:
        redirect_count = 0

    features["nb_redirection"] = redirect_count

    features["ratio_extRedirection"] = (
        1 if redirect_count > 0 else 0
    )

    # -----------------------------------------------------
    # MEDIA
    # -----------------------------------------------------

    media_tags = soup.find_all(
        ["img", "audio", "video", "source"]
    )

    external_media = 0
    internal_media = 0

    for tag in media_tags:

        src = (
            tag.get("src")
            or tag.get("href")
        )

        if not src:
            continue

        if src.startswith("http://") or src.startswith("https://"):

            media_domain = urlparse(src).netloc.lower()

            if hostname in media_domain:
                internal_media += 1
            else:
                external_media += 1

        else:
            internal_media += 1

    total_media = internal_media + external_media

    if total_media > 0:

        features["ratio_extMedia"] = (
            external_media / total_media
        )

        features["ratio_intMedia"] = (
            internal_media / total_media
        )

    else:

        features["ratio_extMedia"] = 0
        features["ratio_intMedia"] = 0

    # -----------------------------------------------------
    # CSS
    # -----------------------------------------------------

    stylesheets = soup.find_all(
        "link",
        rel=lambda value:
        value and "stylesheet" in value
    )

    external_css = 0

    for css in stylesheets:

        href = css.get("href")

        if href and (
            href.startswith("http://")
            or href.startswith("https://")
        ):

            css_domain = urlparse(href).netloc.lower()

            if css_domain != hostname:
                external_css += 1

    features["nb_extCSS"] = external_css

    # -----------------------------------------------------
    # FAVICON
    # -----------------------------------------------------

    favicon = soup.find(
        "link",
        rel=lambda value:
        value and "icon" in value
    )

    if favicon:

        favicon_url = favicon.get("href", "")

        if favicon_url.startswith("http"):

            favicon_domain = urlparse(
                favicon_url
            ).netloc.lower()

            features["external_favicon"] = int(
                favicon_domain != hostname
            )

        else:
            features["external_favicon"] = 0

    else:
        features["external_favicon"] = 0

    # -----------------------------------------------------
    # COPYRIGHT
    # -----------------------------------------------------

    page_text = soup.get_text(
        " ",
        strip=True
    ).lower()

    features["domain_with_copyright"] = int(
        "copyright" in page_text
        and hostname.replace("www.", "")
        in page_text
    )

    # -----------------------------------------------------
    # ERROR RATIO
    # -----------------------------------------------------

    features["ratio_extErrors"] = 0

    return features


# =========================================================
# EXTERNAL FEATURES
# =========================================================

def extract_external_features(url):

    features = {}

    parsed = urlparse(url)

    domain = parsed.netloc.lower().split(":")[0]

    # -----------------------------------------------------
    # DOMAIN AGE / REGISTRATION
    # -----------------------------------------------------

    try:

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        from datetime import datetime

        if creation_date:

            if isinstance(creation_date, datetime):

                age_days = (
                    datetime.now() - creation_date
                ).days

                features["domain_age"] = age_days

            else:
                features["domain_age"] = 0

        else:
            features["domain_age"] = 0

        if expiration_date:

            if isinstance(expiration_date, datetime):

                registration_length = (
                    expiration_date - creation_date
                ).days

                features[
                    "domain_registration_length"
                ] = registration_length

            else:
                features[
                    "domain_registration_length"
                ] = 0

        else:

            features[
                "domain_registration_length"
            ] = 0

    except Exception:

        features["domain_age"] = 0
        features["domain_registration_length"] = 0

    # -----------------------------------------------------
    # GOOGLE INDEX
    # -----------------------------------------------------

    # Placeholder until an external search API is connected.
    # Do NOT silently use this as a real Google index result.

    features["google_index"] = 0

    # -----------------------------------------------------
    # PAGE RANK
    # -----------------------------------------------------

    # Requires an external PageRank/reputation API.
    features["page_rank"] = 0

    # -----------------------------------------------------
    # WEB TRAFFIC
    # -----------------------------------------------------

    # Requires an external traffic-ranking service.
    features["web_traffic"] = 0

    return features


# =========================================================
# MAIN FEATURE EXTRACTION FUNCTION
# =========================================================

def extract_features(url):

    features = {}

    # URL features
    features.update(
        extract_url_features(url)
    )

    # Webpage features
    features.update(
        extract_webpage_features(url)
    )

    # External features
    features.update(
        extract_external_features(url)
    )

    return features
