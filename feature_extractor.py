import re
from urllib.parse import urlparse

import tldextract


# ============================================================
# FINAL URL-ONLY FEATURE EXTRACTOR
# Dataset basis:
# Hannousse & Yahiouche (2020)
# "Web page phishing detection", Mendeley Data V2
#
# This extractor calculates ONLY the 43 URL-based features
# selected by the final Random Forest model.
#
# IMPORTANT:
# - It does NOT download webpages.
# - It does NOT make a phishing/legitimate decision.
# - Prediction must remain inside app.py using the trained model.
# ============================================================


# Use tldextract without downloading the Public Suffix List at runtime.
_TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=None
)


# ============================================================
# EXACT 43 FEATURES USED BY THE FINAL MODEL
# ============================================================

SELECTED_FEATURES = [
    "phish_hints",
    "longest_words_raw",
    "nb_www",
    "length_url",
    "length_hostname",
    "shortest_word_host",
    "nb_slash",
    "nb_hyphens",
    "char_repeat",
    "longest_word_host",
    "shortest_word_path",
    "ratio_digits_host",
    "nb_dots",
    "shortest_words_raw",
    "domain_in_brand",
    "nb_qm",
    "nb_underscore",
    "ip",
    "https_token",
    "nb_subdomains",
    "prefix_suffix",
    "suspecious_tld",
    "shortening_service",
    "nb_com",
    "nb_and",
    "tld_in_path",
    "nb_percent",
    "nb_space",
    "tld_in_subdomain",
    "nb_at",
    "nb_semicolumn",
    "nb_tilde",
    "nb_colon",
    "http_in_path",
    "nb_dslash",
    "brand_in_subdomain",
    "brand_in_path",
    "nb_comma",
    "port",
    "path_extension",
    "punycode",
    "nb_star",
    "nb_dollar",
]


# ============================================================
# ORIGINAL PHISH-HINT LIST
# ============================================================

PHISH_HINTS = [
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
]


# ============================================================
# ORIGINAL SUSPICIOUS TLD LIST
# Keep the original dataset spelling:
# "suspecious_tld"
# ============================================================

SUSPECIOUS_TLDS = [
    "fit",
    "tk",
    "gp",
    "ga",
    "work",
    "ml",
    "date",
    "wang",
    "men",
    "icu",
    "online",
    "click",
    "country",
    "stream",
    "download",
    "xin",
    "racing",
    "jetzt",
    "ren",
    "mom",
    "party",
    "review",
    "trade",
    "accountants",
    "science",
    "work",
    "ninja",
    "xyz",
    "faith",
    "zip",
    "cricket",
    "win",
    "accountant",
    "realtor",
    "top",
    "christmas",
    "gdn",
    "link",
    "asia",
    "club",
    "la",
    "ae",
    "exposed",
    "pe",
    "go.id",
    "rs",
    "k12.pa.us",
    "or.kr",
    "ce.ke",
    "audio",
    "gob.pe",
    "gov.az",
    "website",
    "bj",
    "mx",
    "media",
    "sa.gov.au",
]


# ============================================================
# ORIGINAL URL SHORTENING REGEX
# ============================================================

SHORTENING_PATTERN = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|"
    r"tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|"
    r"tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|"
    r"snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|"
    r"wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
    r"db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|"
    r"tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|po\.st|"
    r"bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|"
    r"u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|"
    r"filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|"
    r"v\.gd|tr\.im|link\.zip\.net"
)


# ============================================================
# ORIGINAL BRAND LIST
# ============================================================

ALL_BRANDS = {
    "accenture",
    "activisionblizzard",
    "adidas",
    "adobe",
    "adultfriendfinder",
    "agriculturalbankofchina",
    "akamai",
    "alibaba",
    "aliexpress",
    "alipay",
    "alliance",
    "alliancedata",
    "allianceone",
    "allianz",
    "alphabet",
    "amazon",
    "americanairlines",
    "americanexpress",
    "americantower",
    "andersons",
    "apache",
    "apple",
    "arrow",
    "ashleymadison",
    "audi",
    "autodesk",
    "avaya",
    "avisbudget",
    "avon",
    "axa",
    "badoo",
    "baidu",
    "bankofamerica",
    "bankofchina",
    "bankofnewyorkmellon",
    "barclays",
    "barnes",
    "bbc",
    "bbt",
    "bbva",
    "bebo",
    "benchmark",
    "bestbuy",
    "bim",
    "bing",
    "biogen",
    "blackstone",
    "blogger",
    "blogspot",
    "bmw",
    "bnpparibas",
    "boeing",
    "booking",
    "broadcom",
    "burberry",
    "caesars",
    "canon",
    "cardinalhealth",
    "carmax",
    "carters",
    "caterpillar",
    "cheesecakefactory",
    "chinaconstructionbank",
    "cinemark",
    "cintas",
    "cisco",
    "citi",
    "citigroup",
    "cnet",
    "coca-cola",
    "colgate",
    "colgate-palmolive",
    "columbiasportswear",
    "commonwealth",
    "communityhealth",
    "continental",
    "dell",
    "deltaairlines",
    "deutschebank",
    "disney",
    "dolby",
    "dominos",
    "donaldson",
    "dreamworks",
    "dropbox",
    "eastman",
    "eastmankodak",
    "ebay",
    "edison",
    "electronicarts",
    "equifax",
    "equinix",
    "expedia",
    "express",
    "facebook",
    "fedex",
    "flickr",
    "footlocker",
    "ford",
    "fordmotor",
    "fossil",
    "fosterwheeler",
    "foxconn",
    "fujitsu",
    "gap",
    "gartner",
    "genesis",
    "genuine",
    "genworth",
    "gigamedia",
    "gillette",
    "github",
    "global",
    "globalpayments",
    "goodyeartire",
    "google",
    "gucci",
    "harley-davidson",
    "harris",
    "hewlettpackard",
    "hilton",
    "hiltonworldwide",
    "hmstatil",
    "honda",
    "hsbc",
    "huawei",
    "huntingtonbancshares",
    "hyundai",
    "ibm",
    "ikea",
    "imdb",
    "imgur",
    "ingbank",
    "insight",
    "instagram",
    "intel",
    "jackdaniels",
    "jnj",
    "jpmorgan",
    "jpmorganchase",
    "kelly",
    "kfc",
    "kindermorgan",
    "lbrands",
    "lego",
    "lennox",
    "lenovo",
    "lindsay",
    "linkedin",
    "livejasmin",
    "loreal",
    "louisvuitton",
    "mastercard",
    "mcdonalds",
    "mckesson",
    "mckinsey",
    "mercedes-benz",
    "microsoft",
    "microsoftonline",
    "mini",
    "mitsubishi",
    "morganstanley",
    "motorola",
    "mrcglobal",
    "mtv",
    "myspace",
    "nescafe",
    "nestle",
    "netflix",
    "nike",
    "nintendo",
    "nissan",
    "nissanmotor",
    "nvidia",
    "nytimes",
    "oracle",
    "panasonic",
    "paypal",
    "pepsi",
    "pepsico",
    "philips",
    "pinterest",
    "pocket",
    "pornhub",
    "porsche",
    "prada",
    "rabobank",
    "reddit",
    "regal",
    "royalbankofcanada",
    "samsung",
    "scotiabank",
    "shell",
    "siemens",
    "skype",
    "snapchat",
    "sony",
    "soundcloud",
    "spiritairlines",
    "spotify",
    "sprite",
    "stackexchange",
    "stackoverflow",
    "starbucks",
    "swatch",
    "swift",
    "symantec",
    "synaptics",
    "target",
    "telegram",
    "tesla",
    "teslamotors",
    "theguardian",
    "homedepot",
    "piratebay",
    "tiffany",
    "tinder",
    "tmall",
    "toyota",
    "tripadvisor",
    "tumblr",
    "twitch",
    "twitter",
    "underarmour",
    "unilever",
    "universal",
    "ups",
    "verizon",
    "viber",
    "visa",
    "volkswagen",
    "volvocars",
    "walmart",
    "wechat",
    "weibo",
    "whatsapp",
    "wikipedia",
    "wordpress",
    "yahoo",
    "yamaha",
    "yandex",
    "youtube",
    "zara",
    "zebra",
    "iphone",
    "icloud",
    "itunes",
    "sinara",
    "normshield",
    "bga",
    "sinaralabs",
    "roksit",
    "cybrml",
    "turkcell",
    "n11",
    "hepsiburada",
    "migros",
}


# ============================================================
# CUSTOM ERROR
# ============================================================

class FeatureExtractionError(Exception):
    pass


# ============================================================
# BASIC URL NORMALIZATION
# ============================================================

def normalize_url(url):
    """
    Add a scheme only when the user omitted one.

    The trained dataset contains complete URLs, so the application
    should pass a complete URL into the extractor.
    """

    url = str(url).strip()

    if not url:
        raise FeatureExtractionError("Please enter a URL.")

    if not url.lower().startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise FeatureExtractionError("Invalid URL.")

    return url


# ============================================================
# WORD EXTRACTION
# Matches the dataset's words_raw_extraction().
# ============================================================

def _words_raw_extraction(domain, subdomain, path):

    split_pattern = r"-|\.|/|\?|\=|\@|\&|\%|\:|\_"

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

    raw_words = (
        domain_words
        + path_words
        + subdomain_words
    )

    host_words = (
        domain_words
        + subdomain_words
    )

    raw_words = list(
        filter(None, raw_words)
    )

    host_words = list(
        filter(None, host_words)
    )

    path_words = list(
        filter(None, path_words)
    )

    return (
        raw_words,
        host_words,
        path_words
    )


# ============================================================
# WORD STATISTICS
# ============================================================

def _shortest_word_length(words):

    if len(words) == 0:
        return 0

    return min(
        len(word)
        for word in words
    )


def _longest_word_length(words):

    if len(words) == 0:
        return 0

    return max(
        len(word)
        for word in words
    )


def _char_repeat(words_raw):
    """
    Matches the original dataset's consecutive-character
    repetition calculation for lengths 2, 3, 4 and 5.
    """

    total = 0

    for word in words_raw:

        for repeat_size in [
            2,
            3,
            4,
            5
        ]:

            for i in range(
                len(word)
                - repeat_size
                + 1
            ):

                part = word[
                    i:
                    i + repeat_size
                ]

                if (
                    len(part) > 0
                    and all(
                        character == part[0]
                        for character
                        in part
                    )
                ):
                    total += 1

    return total


# ============================================================
# URL FEATURE HELPERS
# ============================================================

def _having_ip_address(url):

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

    return 1 if pattern.search(url) else 0


def _phish_hints(url):

    count = 0

    for hint in PHISH_HINTS:
        count += url.lower().count(
            hint
        )

    return count


def _check_www(words_raw):

    count = 0

    for word in words_raw:

        if word.find("www") != -1:
            count += 1

    return count


def _check_com(words_raw):

    count = 0

    for word in words_raw:

        if word.find("com") != -1:
            count += 1

    return count


def _https_token(scheme):
    """
    IMPORTANT:
    Original dataset encoding:
        HTTPS -> 0
        anything else -> 1
    """

    if scheme == "https":
        return 0

    return 1


def _count_subdomain(url):
    """
    Matches the original source implementation.

    Note: despite the feature name, the original implementation
    counts dots in the FULL URL and compresses the result to 1/2/3.
    """

    number_of_dots = len(
        re.findall(r"\.", url)
    )

    if number_of_dots == 1:
        return 1

    elif number_of_dots == 2:
        return 2

    else:
        return 3


def _prefix_suffix(url):

    if re.findall(
        r"https?://[^\-]+-[^\-]+/",
        url
    ):
        return 1

    return 0


def _suspecious_tld(tld):

    if tld in SUSPECIOUS_TLDS:
        return 1

    return 0


def _shortening_service(url):

    if SHORTENING_PATTERN.search(url):
        return 1

    return 0


def _tld_in_path(tld, path):

    if tld and path.lower().count(
        tld
    ) > 0:
        return 1

    return 0


def _tld_in_subdomain(tld, subdomain):

    if tld and subdomain.count(
        tld
    ) > 0:
        return 1

    return 0


def _count_tilde(url):
    """
    Original feature is binary:
        1 if '~' exists
        0 otherwise
    """

    if url.count("~") > 0:
        return 1

    return 0


def _count_double_slash(url):
    """
    Matches the original nb_dslash implementation.

    It is binary, not a raw count.
    """

    positions = [
        match.start(0)
        for match in re.finditer(
            "//",
            url
        )
    ]

    if not positions:
        return 0

    if positions[-1] > 6:
        return 1

    return 0


def _punycode(url):
    """
    Mirrors the original dataset source exactly.

    The original source checks 'http://xn--'.
    """

    if (
        url.startswith("http://xn--")
        or url.startswith("http://xn--")
    ):
        return 1

    return 0


def _port(url):

    pattern = (
        r"^[a-z][a-z0-9+\-.]*://"
        r"([a-z0-9\-._~%!$&'()*+,;=]+@)?"
        r"([a-z0-9\-._~%]+|"
        r"\[[a-z0-9\-._~%!$&'()*+,;=:]+\]):"
        r"([0-9]+)"
    )

    if re.search(
        pattern,
        url
    ):
        return 1

    return 0


def _path_extension(path):

    if path.endswith(
        ".txt"
    ):
        return 1

    return 0


def _domain_in_brand(domain):

    if domain in ALL_BRANDS:
        return 1

    return 0


def _brand_in_location(
    domain,
    location
):
    """
    The original code uses the same function for:
    - brand_in_subdomain
    - brand_in_path
    """

    for brand in ALL_BRANDS:

        if (
            "." + brand + "."
            in location
            and brand not in domain
        ):
            return 1

    return 0


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    url = normalize_url(
        url
    )

    parsed = urlparse(
        url
    )

    hostname = (
        parsed.hostname
        or ""
    )

    extracted = _TLD_EXTRACT(
        url
    )

    domain = (
        extracted.domain
        or ""
    )

    subdomain = (
        extracted.subdomain
        or ""
    )

    tld = (
        extracted.suffix
        or ""
    )

    scheme = (
        parsed.scheme
        or ""
    ).lower()


    # --------------------------------------------------------
    # MATCH THE ORIGINAL DATASET'S PATH CONSTRUCTION
    # --------------------------------------------------------

    if tld:

        tld_position = url.find(
            tld
        )

        if tld_position >= 0:

            temp = url[
                tld_position:
            ]

        else:

            temp = url

    else:

        temp = url


    partitioned = temp.partition(
        "/"
    )

    # Used for http_in_path, tld_in_path and path_extension.
    path = (
        partitioned[1]
        + partitioned[2]
    )

    # Used by word extraction.
    raw_path = partitioned[2]


    (
        words_raw,
        words_raw_host,
        words_raw_path
    ) = _words_raw_extraction(
        domain,
        subdomain,
        raw_path
    )


    # --------------------------------------------------------
    # RATIO DIGITS HOST
    # --------------------------------------------------------

    if len(hostname) > 0:

        ratio_digits_host = (
            len(
                re.sub(
                    r"[^0-9]",
                    "",
                    hostname
                )
            )
            / len(hostname)
        )

    else:

        ratio_digits_host = 0


    # --------------------------------------------------------
    # CREATE EXACT 43 FEATURES
    # --------------------------------------------------------

    features = {

        "phish_hints":
            _phish_hints(
                url
            ),

        "longest_words_raw":
            _longest_word_length(
                words_raw
            ),

        "nb_www":
            _check_www(
                words_raw
            ),

        "length_url":
            len(url),

        "length_hostname":
            len(hostname),

        "shortest_word_host":
            _shortest_word_length(
                words_raw_host
            ),

        "nb_slash":
            url.count("/"),

        "nb_hyphens":
            url.count("-"),

        "char_repeat":
            _char_repeat(
                words_raw
            ),

        "longest_word_host":
            _longest_word_length(
                words_raw_host
            ),

        "shortest_word_path":
            _shortest_word_length(
                words_raw_path
            ),

        "ratio_digits_host":
            ratio_digits_host,

        # The original dataset calls count_dots(url),
        # so this counts dots in the full URL.
        "nb_dots":
            url.count("."),

        "shortest_words_raw":
            _shortest_word_length(
                words_raw
            ),

        "domain_in_brand":
            _domain_in_brand(
                domain
            ),

        "nb_qm":
            url.count("?"),

        "nb_underscore":
            url.count("_"),

        "ip":
            _having_ip_address(
                url
            ),

        "https_token":
            _https_token(
                scheme
            ),

        "nb_subdomains":
            _count_subdomain(
                url
            ),

        "prefix_suffix":
            _prefix_suffix(
                url
            ),

        "suspecious_tld":
            _suspecious_tld(
                tld
            ),

        "shortening_service":
            _shortening_service(
                url
            ),

        "nb_com":
            _check_com(
                words_raw
            ),

        "nb_and":
            url.count("&"),

        "tld_in_path":
            _tld_in_path(
                tld,
                path
            ),

        "nb_percent":
            url.count("%"),

        "nb_space":
            (
                url.count(" ")
                + url.count("%20")
            ),

        "tld_in_subdomain":
            _tld_in_subdomain(
                tld,
                subdomain
            ),

        "nb_at":
            url.count("@"),

        "nb_semicolumn":
            url.count(";"),

        "nb_tilde":
            _count_tilde(
                url
            ),

        "nb_colon":
            url.count(":"),

        "http_in_path":
            path.count(
                "http"
            ),

        "nb_dslash":
            _count_double_slash(
                url
            ),

        # The original master extractor calls brand_in_path()
        # with subdomain for this feature.
        "brand_in_subdomain":
            _brand_in_location(
                domain,
                subdomain
            ),

        "brand_in_path":
            _brand_in_location(
                domain,
                path
            ),

        "nb_comma":
            url.count(","),

        "port":
            _port(
                url
            ),

        "path_extension":
            _path_extension(
                path
            ),

        "punycode":
            _punycode(
                url
            ),

        "nb_star":
            url.count("*"),

        "nb_dollar":
            url.count("$"),
    }


    # --------------------------------------------------------
    # SAFETY CHECK
    # --------------------------------------------------------

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


    # Return only the selected features,
    # in the exact model feature order.
    return {
        feature:
            features[feature]
        for feature
        in SELECTED_FEATURES
    }
