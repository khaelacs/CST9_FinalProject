import re
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup


# ============================================================
# SETTINGS
# ============================================================

CONNECT_TIMEOUT = 3
READ_TIMEOUT = 6
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
# EXACT FEATURES USED BY THE FINAL MODEL
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
# ORIGINAL DATASET REFERENCE VALUES
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


# Same brand list used by the original dataset.
# Kept as normal strings so there is NO triple-quote syntax problem.

BRANDS = set((
    "accenture activisionblizzard adidas adobe adultfriendfinder "
    "agriculturalbankofchina akamai alibaba aliexpress alipay alliance "
    "alliancedata allianceone allianz alphabet amazon americanairlines "
    "americanexpress americantower andersons apache apple arrow "
    "ashleymadison audi autodesk avaya avisbudget avon axa badoo baidu "
    "bankofamerica bankofchina bankofnewyorkmellon barclays barnes bbc "
    "bbt bbva bebo benchmark bestbuy bim bing biogen blackstone blogger "
    "blogspot bmw bnpparibas boeing booking broadcom burberry caesars "
    "canon cardinalhealth carmax carters caterpillar cheesecakefactory "
    "chinaconstructionbank cinemark cintas cisco citi citigroup cnet "
    "coca-cola colgate colgate-palmolive columbiasportswear commonwealth "
    "communityhealth continental dell deltaairlines deutschebank disney "
    "dolby dominos donaldson dreamworks dropbox eastman eastmankodak ebay "
    "edison electronicarts equifax equinix expedia express facebook fedex "
    "flickr footlocker ford fordmotor fossil fosterwheeler foxconn fujitsu "
    "gap gartner genesis genuine genworth gigamedia gillette github global "
    "globalpayments goodyeartire google gucci harley-davidson harris "
    "hewlettpackard hilton hiltonworldwide hmstatil honda hsbc huawei "
    "huntingtonbancshares hyundai ibm ikea imdb imgur ingbank insight "
    "instagram intel jackdaniels jnj jpmorgan jpmorganchase kelly kfc "
    "kindermorgan lbrands lego lennox lenovo lindsay linkedin livejasmin "
    "loreal louisvuitton mastercard mcdonalds mckesson mckinsey "
    "mercedes-benz microsoft microsoftonline mini mitsubishi morganstanley "
    "motorola mrcglobal mtv myspace nescafe nestle netflix nike nintendo "
    "nissan nissanmotor nvidia nytimes oracle panasonic paypal pepsi "
    "pepsico philips pinterest pocket pornhub porsche prada rabobank "
    "reddit regal royalbankofcanada samsung scotiabank shell siemens skype "
    "snapchat sony soundcloud spiritairlines spotify sprite stackexchange "
    "stackoverflow starbucks swatch swift symantec synaptics target telegram "
    "tesla teslamotors theguardian homedepot piratebay tiffany tinder tmall "
    "toyota tripadvisor tumblr twitch twitter underarmour unilever universal "
    "ups verizon viber visa volkswagen volvocars walmart wechat weibo "
    "whatsapp wikipedia wordpress yahoo yamaha yandex youtube zara zebra "
    "iphone icloud itunes sinara normshield bga sinaralabs roksit cybrml "
    "turkcell n11 hepsiburada migros"
).split())


NULL_FORMAT = {
    "",
    "#",
    "#nothing",
    "#doesnotexist",
    "#null",
    "#void",
    "#whatever",
    "#content",
    "javascript::void(0)",
    "javascript::void(0);",
    "javascript::;",
    "javascript",
}


# ============================================================
# CUSTOM ERROR
# ============================================================

class FeatureExtractionError(Exception):
    pass


# ============================================================
# BASIC URL HELPERS
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

        url = (
            "https://"
            + url
        )

    parsed = urlparse(
        url
    )

    if not parsed.hostname:

        raise FeatureExtractionError(
            "Invalid website URL."
        )

    return url


def _url_parts(url):

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

def _split_words_like_dataset(
    url,
    domain,
    subdomain,
    suffix
):

    split_pattern = (
        r"-|\.|/|\?|\=|\@|\&|\%|\:|\_"
    )

    if suffix and suffix in url:

        suffix_position = (
            url.find(
                suffix
            )
        )

        remaining_url = url[
            suffix_position:
        ]

        partitioned = (
            remaining_url.partition(
                "/"
            )
        )

        path_raw = (
            partitioned[2]
        )

    else:

        parsed = urlparse(
            url
        )

        path_raw = (
            parsed.path.lstrip(
                "/"
            )
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
        path_raw.lower()
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


def _minimum_length(words):

    return min(
        (
            len(word)
            for word in words
        ),
        default=0
    )


def _maximum_length(words):

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

            for i in range(
                len(word)
                - size
                + 1
            ):

                part = word[
                    i:
                    i + size
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

def _having_ip(
    url
):

    pattern = re.compile(
        r"(([01]?\d\d?|2[0-4]\d|25[0-5])\."
        r"([01]?\d\d?|2[0-4]\d|25[0-5])\."
        r"([01]?\d\d?|2[0-4]\d|25[0-5])\."
        r"([01]?\d\d?|2[0-4]\d|25[0-5])\/)|"
        r"((0x[0-9a-fA-F]{1,2})\."
        r"(0x[0-9a-fA-F]{1,2})\."
        r"(0x[0-9a-fA-F]{1,2})\."
        r"(0x[0-9a-fA-F]{1,2})\/)|"
        r"(?:[a-fA-F0-9]{1,4}:){7}"
        r"[a-fA-F0-9]{1,4}|"
        r"[0-9a-fA-F]{7}"
    )

    if pattern.search(
        url
    ):

        return 1

    return 0


# ============================================================
# URL-BASED FEATURES
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
    ) = _url_parts(
        url
    )

    (
        raw_words,
        host_words,
        path_words
    ) = _split_words_like_dataset(
        url,
        domain,
        subdomain,
        suffix
    )

    digits_in_host = len(
        re.sub(
            r"[^0-9]",
            "",
            hostname
        )
    )

    if hostname:

        ratio_digits_host = (
            digits_in_host
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

    domain_in_brand = (
        1
        if domain in BRANDS
        else 0
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
            domain_in_brand,

        "ip":
            _having_ip(
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
            "The website redirected too many times."
        ) from error

    except requests.RequestException as error:

        raise FeatureExtractionError(
            "The webpage could not be downloaded."
        ) from error

    if response.status_code >= 400:

        raise FeatureExtractionError(
            "Website returned HTTP "
            + str(
                response.status_code
            )
            + "."
        )

    content = (
        response.content
    )

    if not content:

        raise FeatureExtractionError(
            "The webpage returned no content."
        )

    if (
        len(content)
        > MAX_HTML_BYTES
    ):

        raise FeatureExtractionError(
            "The webpage is too large to analyze."
        )

    return content


# ============================================================
# HTML COLLECTION HELPERS
# ============================================================

def _collection():

    return {
        "internals": [],
        "externals": [],
        "null": []
    }


def _looks_internal(
    value,
    hostname,
    registered_domain
):

    dots = len(
        re.findall(
            r"\.",
            value
        )
    )

    return (
        hostname in value
        or registered_domain in value
        or dots == 1
        or not value.startswith(
            "http"
        )
    )


def _add_resource(
    target,
    value,
    hostname,
    registered_domain
):

    value = (
        value
        or ""
    ).strip()

    internal = (
        _looks_internal(
            value,
            hostname,
            registered_domain
        )
    )

    if internal:

        # Matches the behavior used by the
        # original dataset extraction code.

        if not value.startswith(
            "http"
        ):

            if not value.startswith(
                "/"
            ):

                target[
                    "internals"
                ].append(
                    hostname
                    + "/"
                    + value
                )

            elif value in NULL_FORMAT:

                target[
                    "null"
                ].append(
                    value
                )

            else:

                target[
                    "internals"
                ].append(
                    hostname
                    + value
                )

    else:

        target[
            "externals"
        ].append(
            value
        )


# ============================================================
# COLLECT WEBPAGE DATA
# ============================================================

def _collect_page_data(
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
    ) = _url_parts(
        url
    )

    soup = BeautifulSoup(
        html,
        "html.parser",
        from_encoding="iso-8859-1"
    )

    href = _collection()
    link = _collection()
    media = _collection()
    form = _collection()
    css = _collection()
    favicon = _collection()

    anchor = {
        "safe": [],
        "unsafe": [],
        "null": []
    }


    # ========================================================
    # ANCHOR TAGS
    # ========================================================

    for tag in soup.find_all(
        "a",
        href=True
    ):

        value = (
            tag.get(
                "href"
            )
            or ""
        ).strip()

        internal = (
            _looks_internal(
                value,
                hostname,
                registered_domain
            )
        )

        if internal:

            lower_value = (
                value.lower()
            )

            if (
                "#"
                in value
                or "javascript"
                in lower_value
                or "mailto"
                in lower_value
            ):

                anchor[
                    "unsafe"
                ].append(
                    value
                )

        else:

            anchor[
                "safe"
            ].append(
                value
            )

        _add_resource(
            href,
            value,
            hostname,
            registered_domain
        )


    # ========================================================
    # MEDIA
    # ========================================================

    for tag_name in (
        "img",
        "audio",
        "embed",
        "iframe"
    ):

        for tag in soup.find_all(
            tag_name,
            src=True
        ):

            _add_resource(
                media,
                tag.get(
                    "src"
                ),
                hostname,
                registered_domain
            )


    # ========================================================
    # LINK TAGS
    # ========================================================

    for tag in soup.find_all(
        "link",
        href=True
    ):

        _add_resource(
            link,
            tag.get(
                "href"
            ),
            hostname,
            registered_domain
        )


    # ========================================================
    # SCRIPT TAGS
    # ========================================================

    for tag in soup.find_all(
        "script",
        src=True
    ):

        _add_resource(
            link,
            tag.get(
                "src"
            ),
            hostname,
            registered_domain
        )


    # ========================================================
    # CSS
    # ========================================================

    for tag in soup.find_all(
        "link",
        rel="stylesheet"
    ):

        if tag.get(
            "href"
        ):

            _add_resource(
                css,
                tag.get(
                    "href"
                ),
                hostname,
                registered_domain
            )


    for style in soup.find_all(
        "style"
    ):

        style_text = (
            style.string
            or style.get_text()
            or ""
        )

        match = re.search(
            r"@import\s+url\(([^)]+)\)",
            style_text,
            flags=re.IGNORECASE
        )

        if match:

            imported_url = (
                match.group(
                    1
                )
                .strip()
                .strip(
                    "'\""
                )
            )

            _add_resource(
                css,
                imported_url,
                hostname,
                registered_domain
            )


    # ========================================================
    # FORMS
    # ========================================================

    for tag in soup.find_all(
        "form",
        action=True
    ):

        _add_resource(
            form,
            tag.get(
                "action"
            ),
            hostname,
            registered_domain
        )


    # ========================================================
    # FAVICON / HEAD LINKS
    # ========================================================

    head = soup.find(
        "head"
    )

    if head:

        # Original extractor counted head links.

        for tag in head.find_all(
            "link",
            href=True
        ):

            _add_resource(
                favicon,
                tag.get(
                    "href"
                ),
                hostname,
                registered_domain
            )


        # It also counted icon links.

        for tag in head.find_all(
            "link",
            href=True
        ):

            rel = tag.get(
                "rel",
                []
            )

            if isinstance(
                rel,
                str
            ):

                rel = [
                    rel
                ]

            is_icon = any(
                str(
                    value
                )
                .lower()
                .endswith(
                    "icon"
                )
                for value in rel
            )

            if is_icon:

                _add_resource(
                    favicon,
                    tag.get(
                        "href"
                    ),
                    hostname,
                    registered_domain
                )


    # ========================================================
    # TITLE
    # ========================================================

    title = ""

    try:

        if (
            soup.title
            and soup.title.string
        ):

            title = str(
                soup.title.string
            )

    except Exception:

        title = ""


    page_text = (
        soup.get_text()
    )


    return {

        "domain":
            domain,

        "href":
            href,

        "link":
            link,

        "media":
            media,

        "form":
            form,

        "css":
            css,

        "favicon":
            favicon,

        "anchor":
            anchor,

        "title":
            title,

        "text":
            page_text,
    }


# ============================================================
# WEBPAGE FEATURES
# ============================================================

def extract_webpage_features(
    url,
    html
):

    data = _collect_page_data(
        url,
        html
    )

    groups = (
        data["href"],
        data["link"],
        data["media"],
        data["form"],
        data["css"],
        data["favicon"]
    )


    # ========================================================
    # HYPERLINK COUNTS
    # ========================================================

    internal_count = sum(
        len(
            group[
                "internals"
            ]
        )
        for group in groups
    )

    external_count = sum(
        len(
            group[
                "externals"
            ]
        )
        for group in groups
    )

    total_hyperlinks = (
        internal_count
        + external_count
    )


    if total_hyperlinks:

        ratio_int_hyperlinks = (
            internal_count
            / total_hyperlinks
        )

        ratio_ext_hyperlinks = (
            external_count
            / total_hyperlinks
        )

    else:

        ratio_int_hyperlinks = 0
        ratio_ext_hyperlinks = 0


    # ========================================================
    # SAFE ANCHOR
    # ========================================================

    anchor = data[
        "anchor"
    ]

    anchor_total = (
        len(
            anchor[
                "safe"
            ]
        )
        +
        len(
            anchor[
                "unsafe"
            ]
        )
    )

    if anchor_total:

        safe_anchor = (
            len(
                anchor[
                    "unsafe"
                ]
            )
            / anchor_total
            * 100
        )

    else:

        safe_anchor = 0


    # ========================================================
    # MEDIA RATIOS
    # ========================================================

    media = data[
        "media"
    ]

    media_internal = len(
        media[
            "internals"
        ]
    )

    media_external = len(
        media[
            "externals"
        ]
    )

    media_total = (
        media_internal
        + media_external
    )

    if media_total:

        ratio_int_media = (
            media_internal
            / media_total
            * 100
        )

        ratio_ext_media = (
            media_external
            / media_total
            * 100
        )

    else:

        ratio_int_media = 0
        ratio_ext_media = 0


    # ========================================================
    # DOMAIN IN TITLE
    # ========================================================

    domain = data[
        "domain"
    ]

    title = (
        data[
            "title"
        ]
        or ""
    )

    # Dataset encoding:
    #
    # 0 = domain appears in title
    # 1 = domain does NOT appear in title

    if (
        domain.lower()
        in title.lower()
    ):

        domain_in_title = 0

    else:

        domain_in_title = 1


    # ========================================================
    # DOMAIN WITH COPYRIGHT
    # ========================================================

    page_text = (
        data[
            "text"
        ]
        or ""
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
            len(
                page_text
            ),
            copyright_symbol.start()
            + 50
        )

        nearby_text = (
            page_text[
                start:
                end
            ]
        )

        if (
            domain.lower()
            in nearby_text.lower()
        ):

            domain_with_copyright = 0

        else:

            domain_with_copyright = 1

    else:

        # This matches the original feature function.
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

    # --------------------------------------------------------
    # NORMALIZE URL
    # --------------------------------------------------------

    url = normalize_url(
        url
    )


    # --------------------------------------------------------
    # URL FEATURES
    # --------------------------------------------------------

    url_features = (
        extract_url_features(
            url
        )
    )


    # --------------------------------------------------------
    # DOWNLOAD ONLY THE MAIN WEBPAGE
    # --------------------------------------------------------

    html = _download_html(
        url
    )


    # --------------------------------------------------------
    # HTML FEATURES
    # --------------------------------------------------------

    webpage_features = (
        extract_webpage_features(
            url,
            html
        )
    )


    # --------------------------------------------------------
    # COMBINE
    # --------------------------------------------------------

    features = {
        **url_features,
        **webpage_features
    }


    # --------------------------------------------------------
    # VERIFY ALL MODEL FEATURES EXIST
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in SELECTED_FEATURES
        if feature not in features
    ]

    if missing_features:

        raise FeatureExtractionError(
            "Missing extracted features: "
            + ", ".join(
                missing_features
            )
        )


    # --------------------------------------------------------
    # RETURN ONLY THE EXACT 25 MODEL FEATURES
    # IN THE EXACT TRAINING ORDER
    # --------------------------------------------------------

    return {
        feature:
            features[
                feature
            ]
        for feature in SELECTED_FEATURES
    }
