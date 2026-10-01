import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup


# ============================================================
# SETTINGS
# ============================================================

CONNECT_TIMEOUT = 3
READ_TIMEOUT = 6
DNS_TIMEOUT = 2
MAX_REDIRECTS = 3
MAX_HTML_BYTES = 3 * 1024 * 1024

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0 Safari/537.36"
    )
}

_TLD = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ============================================================
# EXACT 25 FEATURES USED BY FINAL MODEL
# ============================================================

SELECTED_FEATURES = [
    "nb_hyperlinks",
    "phish_hints",
    "nb_www",
    "safe_anchor",
    "ratio_extHyperlinks",
    "longest_words_raw",
    "ratio_intHyperlinks",
    "length_url",
    "shortest_word_host",
    "nb_slash",
    "length_hostname",
    "domain_in_title",
    "char_repeat",
    "shortest_word_path",
    "longest_word_host",
    "nb_hyphens",
    "domain_with_copyright",
    "nb_dots",
    "ratio_digits_host",
    "shortest_words_raw",
    "ratio_intMedia",
    "domain_in_brand",
    "ratio_extMedia",
    "ip",
    "nb_qm",
]


# ============================================================
# REFERENCE VALUES
# ============================================================

PHISH_HINTS = (
    "wp",
    "login",
    "includes",
    "admin",
    "content",
    "site",
    "images",
    "js",
    "alibaba",
    "css",
    "myaccount",
    "dropbox",
    "themes",
    "plugins",
    "signin",
    "view",
)


BRANDS = {
    "adidas",
    "adobe",
    "alibaba",
    "aliexpress",
    "amazon",
    "americanexpress",
    "apple",
    "bankofamerica",
    "barclays",
    "bbc",
    "bestbuy",
    "bing",
    "bmw",
    "booking",
    "cisco",
    "citi",
    "citigroup",
    "dell",
    "disney",
    "dropbox",
    "ebay",
    "facebook",
    "fedex",
    "ford",
    "github",
    "google",
    "gucci",
    "honda",
    "hsbc",
    "huawei",
    "ibm",
    "ikea",
    "instagram",
    "intel",
    "linkedin",
    "mastercard",
    "microsoft",
    "netflix",
    "nike",
    "nintendo",
    "nissan",
    "oracle",
    "paypal",
    "pinterest",
    "reddit",
    "samsung",
    "skype",
    "snapchat",
    "sony",
    "spotify",
    "starbucks",
    "telegram",
    "tesla",
    "tiktok",
    "toyota",
    "tripadvisor",
    "tumblr",
    "twitch",
    "twitter",
    "visa",
    "volkswagen",
    "walmart",
    "wechat",
    "whatsapp",
    "wikipedia",
    "wordpress",
    "yahoo",
    "youtube",
}


NULL_FORMAT = {
    "",
    "#",
    "#nothing",
    "#doesnotexist",
    "#null",
    "#void",
    "#whatever",
    "#content",
    "javascript:void(0)",
    "javascript:void(0);",
    "javascript::void(0)",
    "javascript::void(0);",
    "javascript",
}


# ============================================================
# CUSTOM ERROR
# ============================================================

class FeatureExtractionError(Exception):
    pass


# ============================================================
# NORMALIZE URL
# ============================================================

def normalize_url(url):

    url = str(url).strip()

    if not url:
        raise FeatureExtractionError(
            "Please enter a website URL."
        )

    if not url.lower().startswith(
        (
            "http://",
            "https://"
        )
    ):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise FeatureExtractionError(
            "Invalid website URL."
        )

    return url


# ============================================================
# PROTECT STREAMLIT SERVER FROM PRIVATE / LOCAL URLS
# ============================================================

def _is_private_ip(address):

    ip = ipaddress.ip_address(
        address
    )

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_hostname(
    hostname
):

    def lookup():

        return socket.getaddrinfo(
            hostname,
            None
        )

    with ThreadPoolExecutor(
        max_workers=1
    ) as executor:

        future = executor.submit(
            lookup
        )

        try:

            return future.result(
                timeout=DNS_TIMEOUT
            )

        except TimeoutError as error:

            raise FeatureExtractionError(
                "DNS lookup timed out."
            ) from error

        except socket.gaierror as error:

            raise FeatureExtractionError(
                "Website hostname could not be resolved."
            ) from error


def _validate_public_url(
    url
):

    parsed = urlparse(
        url
    )

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    if not hostname:

        raise FeatureExtractionError(
            "Invalid hostname."
        )

    if hostname in {
        "localhost",
        "localhost.localdomain"
    }:

        raise FeatureExtractionError(
            "Local URLs are not supported."
        )

    try:

        literal_ip = ipaddress.ip_address(
            hostname
        )

        if _is_private_ip(
            str(literal_ip)
        ):

            raise FeatureExtractionError(
                "Private/local network URLs are not supported."
            )

        return

    except ValueError:

        pass


    records = _resolve_hostname(
        hostname
    )

    for record in records:

        address = record[4][0]

        try:

            if _is_private_ip(
                address
            ):

                raise FeatureExtractionError(
                    "Private/local network URLs are not supported."
                )

        except ValueError:

            continue


# ============================================================
# URL INFORMATION
# ============================================================

def _get_url_information(
    url
):

    parsed = urlparse(
        url
    )

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    extracted = _TLD(
        url
    )

    domain = (
        extracted.domain
        or ""
    ).lower()

    suffix = (
        extracted.suffix
        or ""
    ).lower()

    subdomain = (
        extracted.subdomain
        or ""
    ).lower()

    if domain and suffix:

        registered_domain = (
            domain
            + "."
            + suffix
        )

    else:

        registered_domain = (
            hostname
        )

    return (
        parsed,
        hostname,
        domain,
        suffix,
        subdomain,
        registered_domain
    )


# ============================================================
# WORD EXTRACTION
# ============================================================

def _extract_words(
    url,
    domain,
    subdomain,
    suffix
):

    split_pattern = (
        r"-|\.|/|\?|\=|\@|\&|\%|\:|\_"
    )

    if suffix and suffix in url:

        position = url.find(
            suffix
        )

        remaining = url[
            position:
        ]

        path = remaining.partition(
            "/"
        )[2]

    else:

        path = urlparse(
            url
        ).path.lstrip(
            "/"
        )


    domain_words = re.split(
        split_pattern,
        domain.lower()
    )

    subdomain_words = re.split(
        split_pattern,
        subdomain.lower()
    )

    path_words = re.split(
        split_pattern,
        path.lower()
    )


    raw_words = [
        word
        for word in (
            domain_words
            + path_words
            + subdomain_words
        )
        if word
    ]

    host_words = [
        word
        for word in (
            domain_words
            + subdomain_words
        )
        if word
    ]

    path_words = [
        word
        for word in path_words
        if word
    ]

    return (
        raw_words,
        host_words,
        path_words
    )


def _minimum_length(
    words
):

    return min(
        (
            len(word)
            for word in words
        ),
        default=0
    )


def _maximum_length(
    words
):

    return max(
        (
            len(word)
            for word in words
        ),
        default=0
    )


# ============================================================
# CHARACTER REPETITION
# ============================================================

def _char_repeat(
    words
):

    total = 0

    for word in words:

        for size in (
            2,
            3,
            4,
            5
        ):

            for index in range(
                len(word)
                - size
                + 1
            ):

                part = word[
                    index:
                    index + size
                ]

                if (
                    part
                    and all(
                        character
                        == part[0]
                        for character
                        in part
                    )
                ):

                    total += 1

    return total


# ============================================================
# IP FEATURE
# ============================================================

def _has_ip(
    url
):

    hostname = (
        urlparse(
            url
        ).hostname
        or ""
    )

    try:

        ipaddress.ip_address(
            hostname
        )

        return 1

    except ValueError:

        return 0


# ============================================================
# URL FEATURES
# ============================================================

def extract_url_features(
    url
):

    (
        parsed,
        hostname,
        domain,
        suffix,
        subdomain,
        registered_domain
    ) = _get_url_information(
        url
    )


    (
        raw_words,
        host_words,
        path_words
    ) = _extract_words(
        url,
        domain,
        subdomain,
        suffix
    )


    digit_count = sum(
        character.isdigit()
        for character
        in hostname
    )


    if hostname:

        ratio_digits_host = (
            digit_count
            / len(hostname)
        )

    else:

        ratio_digits_host = 0


    phish_hints = sum(
        url.lower().count(
            hint
        )
        for hint in PHISH_HINTS
    )


    nb_www = sum(
        1
        for word in raw_words
        if "www" in word
    )


    return {

        "phish_hints":
            phish_hints,

        "nb_www":
            nb_www,

        "longest_words_raw":
            _maximum_length(
                raw_words
            ),

        "length_url":
            len(url),

        "shortest_word_host":
            _minimum_length(
                host_words
            ),

        "nb_slash":
            url.count(
                "/"
            ),

        "length_hostname":
            len(
                hostname
            ),

        "char_repeat":
            _char_repeat(
                raw_words
            ),

        "shortest_word_path":
            _minimum_length(
                path_words
            ),

        "longest_word_host":
            _maximum_length(
                host_words
            ),

        "nb_hyphens":
            url.count(
                "-"
            ),

        "nb_dots":
            url.count(
                "."
            ),

        "ratio_digits_host":
            ratio_digits_host,

        "shortest_words_raw":
            _minimum_length(
                raw_words
            ),

        "domain_in_brand":
            (
                1
                if domain in BRANDS
                else 0
            ),

        "ip":
            _has_ip(
                url
            ),

        "nb_qm":
            url.count(
                "?"
            ),
    }


# ============================================================
# DOWNLOAD WEBPAGE
# ============================================================

def _download_html(
    url
):

    _validate_public_url(
        url
    )

    session = requests.Session()

    session.max_redirects = (
        MAX_REDIRECTS
    )

    try:

        response = session.get(
            url,
            headers=HEADERS,
            timeout=(
                CONNECT_TIMEOUT,
                READ_TIMEOUT
            ),
            allow_redirects=True
        )

    except requests.TooManyRedirects as error:

        raise FeatureExtractionError(
            "Website redirected too many times."
        ) from error

    except requests.RequestException as error:

        raise FeatureExtractionError(
            "Website could not be downloaded."
        ) from error


    if response.status_code >= 400:

        raise FeatureExtractionError(
            "Website returned HTTP "
            + str(
                response.status_code
            )
        )


    content = response.content


    if not content:

        raise FeatureExtractionError(
            "Website returned no HTML content."
        )


    if (
        len(content)
        > MAX_HTML_BYTES
    ):

        raise FeatureExtractionError(
            "Website is too large to analyze."
        )


    return content


# ============================================================
# INTERNAL / EXTERNAL RESOURCE CHECK
# ============================================================

def _is_internal_resource(
    resource,
    hostname,
    registered_domain
):

    resource = (
        resource
        or ""
    ).strip()


    if not resource:

        return True


    if resource.startswith(
        (
            "/",
            "#",
            "?",
            "./",
            "../"
        )
    ):

        return True


    if resource.lower().startswith(
        (
            "javascript:",
            "mailto:",
            "tel:"
        )
    ):

        return True


    parsed = urlparse(
        resource
    )


    resource_hostname = (
        parsed.hostname
        or ""
    ).lower()


    if not resource_hostname:

        return True


    resource_tld = _TLD(
        resource_hostname
    )


    if (
        resource_tld.domain
        and resource_tld.suffix
    ):

        resource_registered = (
            resource_tld.domain
            + "."
            + resource_tld.suffix
        ).lower()

    else:

        resource_registered = (
            resource_hostname
        )


    return (
        resource_hostname
        == hostname
        or resource_registered
        == registered_domain
    )


# ============================================================
# WEBPAGE FEATURES
# ============================================================

def extract_webpage_features(
    url,
    html
):

    (
        parsed,
        hostname,
        domain,
        suffix,
        subdomain,
        registered_domain
    ) = _get_url_information(
        url
    )


    soup = BeautifulSoup(
        html,
        "html.parser"
    )


    # ========================================================
    # HYPERLINKS
    # ========================================================

    anchors = soup.find_all(
        "a",
        href=True
    )


    internal_links = 0
    external_links = 0

    unsafe_anchors = 0
    anchor_count = 0


    for anchor in anchors:

        href = (
            anchor.get(
                "href"
            )
            or ""
        ).strip()


        if not href:

            continue


        anchor_count += 1


        href_lower = href.lower()


        if (
            href_lower in NULL_FORMAT
            or href.startswith(
                "#"
            )
            or href_lower.startswith(
                "javascript:"
            )
            or href_lower.startswith(
                "mailto:"
            )
        ):

            unsafe_anchors += 1


        if _is_internal_resource(
            href,
            hostname,
            registered_domain
        ):

            internal_links += 1

        else:

            external_links += 1


    total_hyperlinks = (
        internal_links
        + external_links
    )


    if total_hyperlinks:

        ratio_int_hyperlinks = (
            internal_links
            / total_hyperlinks
        )

        ratio_ext_hyperlinks = (
            external_links
            / total_hyperlinks
        )

    else:

        ratio_int_hyperlinks = 0
        ratio_ext_hyperlinks = 0


    if anchor_count:

        safe_anchor = (
            unsafe_anchors
            / anchor_count
            * 100
        )

    else:

        safe_anchor = 0


    # ========================================================
    # MEDIA
    # ========================================================

    internal_media = 0
    external_media = 0


    for tag_name in (
        "img",
        "audio",
        "video",
        "source",
        "embed",
        "iframe"
    ):

        for tag in soup.find_all(
            tag_name,
            src=True
        ):

            source = (
                tag.get(
                    "src"
                )
                or ""
            ).strip()


            if not source:

                continue


            if _is_internal_resource(
                source,
                hostname,
                registered_domain
            ):

                internal_media += 1

            else:

                external_media += 1


    total_media = (
        internal_media
        + external_media
    )


    if total_media:

        ratio_int_media = (
            internal_media
            / total_media
            * 100
        )

        ratio_ext_media = (
            external_media
            / total_media
            * 100
        )

    else:

        ratio_int_media = 0
        ratio_ext_media = 0


    # ========================================================
    # DOMAIN IN TITLE
    # ========================================================

    title_tag = soup.find(
        "title"
    )


    if title_tag:

        title = title_tag.get_text(
            " ",
            strip=True
        )

    else:

        title = ""


    if (
        domain
        and domain.lower()
        in title.lower()
    ):

        domain_in_title = 0

    else:

        domain_in_title = 1


    # ========================================================
    # DOMAIN WITH COPYRIGHT
    # ========================================================

    page_text = soup.get_text(
        " ",
        strip=True
    )


    copyright_symbol = re.search(
        r"[©™®]",
        page_text
    )


    if copyright_symbol:

        start = max(
            0,
            copyright_symbol.start()
            - 50
        )

        end = min(
            len(page_text),
            copyright_symbol.start()
            + 50
        )


        nearby_text = page_text[
            start:end
        ]


        if (
            domain
            and domain.lower()
            in nearby_text.lower()
        ):

            domain_with_copyright = 0

        else:

            domain_with_copyright = 1

    else:

        domain_with_copyright = 0


    return {

        "nb_hyperlinks":
            total_hyperlinks,

        "safe_anchor":
            safe_anchor,

        "ratio_extHyperlinks":
            ratio_ext_hyperlinks,

        "ratio_intHyperlinks":
            ratio_int_hyperlinks,

        "domain_in_title":
            domain_in_title,

        "domain_with_copyright":
            domain_with_copyright,

        "ratio_intMedia":
            ratio_int_media,

        "ratio_extMedia":
            ratio_ext_media,
    }


# ============================================================
# MAIN FUNCTION USED BY app.py
# ============================================================

def extract_features(
    url
):

    # Normalize URL
    url = normalize_url(
        url
    )


    # URL-based features
    url_features = (
        extract_url_features(
            url
        )
    )


    # Download the webpage once
    html = _download_html(
        url
    )


    # HTML-based features
    webpage_features = (
        extract_webpage_features(
            url,
            html
        )
    )


    # Combine features
    features = {
        **url_features,
        **webpage_features
    }


    # Verify all 25 model features
    missing_features = [
        feature
        for feature in SELECTED_FEATURES
        if feature not in features
    ]


    if missing_features:

        raise FeatureExtractionError(
            "Missing features: "
            + ", ".join(
                missing_features
            )
        )


    # Return ONLY the 25 features used
    # by the Random Forest.
    return {
        feature:
            features[
                feature
            ]
        for feature in SELECTED_FEATURES
    }
