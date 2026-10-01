import requests
import whois
from datetime import datetime
from urllib.parse import urlparse
from functools import lru_cache

from tranco import Tranco


# ============================================================
# DOMAIN AGE AND REGISTRATION LENGTH
# ============================================================

def get_whois_features(domain):
    """
    Get:
    - domain_age
    - domain_registration_length

    Values are measured in days.
    """

    domain_age = -1
    domain_registration_length = -1

    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        # WHOIS may return a list of dates
        if isinstance(creation_date, list):
            creation_date = min(
                d for d in creation_date if d is not None
            )

        if isinstance(expiration_date, list):
            expiration_date = max(
                d for d in expiration_date if d is not None
            )

        now = datetime.now()

        # Domain age
        if creation_date is not None:
            domain_age = max(
                0,
                (now - creation_date).days
            )

        # Registration length
        if (
            creation_date is not None
            and expiration_date is not None
        ):
            domain_registration_length = max(
                0,
                (expiration_date - creation_date).days
            )

    except Exception as e:
        print("WHOIS error:", e)

    return domain_age, domain_registration_length


# ============================================================
# GOOGLE INDEX
# ============================================================

def get_google_index(domain):
    """
    Checks whether Google search results contain the domain.

    Uses Serper's Google Search API as a practical live proxy
    for the original google_index feature.

    Returns:
        1 = domain appears in Google search results
        0 = domain does not appear
    """

    try:
        import streamlit as st

        api_key = st.secrets.get(
            "SERPER_API_KEY",
            ""
        )

        if not api_key:
            raise ValueError(
                "SERPER_API_KEY is missing from Streamlit Secrets."
            )

        response = requests.post(
            "https://google.serper.dev/search",
            headers={
                "X-API-KEY": api_key,
                "Content-Type": "application/json"
            },
            json={
                "q": f"site:{domain}",
                "num": 1
            },
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        organic_results = data.get(
            "organic",
            []
        )

        return 1 if len(organic_results) > 0 else 0

    except Exception as e:
        print("Google index error:", e)
        raise


# ============================================================
# OPEN PAGERANK
# ============================================================

def get_page_rank(domain):
    """
    Get PageRank from OpenPageRank.

    Dataset range:
        0 - 10

    We use page_rank_integer because your training
    dataset contains integer PageRank values.
    """

    try:
        import streamlit as st

        api_key = st.secrets.get(
            "OPENPAGERANK_API_KEY",
            ""
        )

        if not api_key:
            raise ValueError(
                "OPENPAGERANK_API_KEY is missing "
                "from Streamlit Secrets."
            )

        url = (
            "https://openpagerank.keywordseverywhere.com"
            "/api/v1.0/getPageRank"
        )

        response = requests.get(
            url,
            headers={
                "API-OPR": api_key
            },
            params={
                "domains[]": domain
            },
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        results = data.get(
            "response",
            []
        )

        if len(results) == 0:
            return 0

        result = results[0]

        if result.get("status_code") != 200:
            return 0

        return int(
            result.get(
                "page_rank_integer",
                0
            )
        )

    except Exception as e:
        print("PageRank error:", e)
        raise


# ============================================================
# TRANCO WEB TRAFFIC / POPULARITY RANK
# ============================================================

@lru_cache(maxsize=1)
def get_tranco_list():
    """
    Download and cache the latest Tranco ranking.

    The list is cached so it isn't downloaded every time
    a user checks a URL.
    """

    t = Tranco(
        cache=True,
        cache_dir=".tranco"
    )

    return t.list()


def get_web_traffic(domain):
    """
    Get the current Tranco rank.

    Example:
        Google may have a very low rank number.
        Unknown domains return 0.

    This is a modern popularity-rank proxy for the
    historical web_traffic feature.
    """

    try:
        tranco_list = get_tranco_list()

        rank = tranco_list.rank(domain)

        if rank == -1:
            return 0

        return int(rank)

    except Exception as e:
        print("Tranco error:", e)
        raise


# ============================================================
# EXTERNAL FEATURES
# ============================================================

def extract_external_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # Remove username/password if present
    if "@" in domain:
        domain = domain.split("@")[-1]

    # Remove port
    domain = domain.split(":")[0]

    # Remove www
    if domain.startswith("www."):
        domain = domain[4:]

    # --------------------------------------------------------
    # WHOIS
    # --------------------------------------------------------

    domain_age, domain_registration_length = (
        get_whois_features(domain)
    )

    # --------------------------------------------------------
    # GOOGLE INDEX
    # --------------------------------------------------------

    google_index = get_google_index(domain)

    # --------------------------------------------------------
    # PAGE RANK
    # --------------------------------------------------------

    page_rank = get_page_rank(domain)

    # --------------------------------------------------------
    # WEB TRAFFIC
    # --------------------------------------------------------

    web_traffic = get_web_traffic(domain)

    # --------------------------------------------------------
    # RETURN FEATURES
    # --------------------------------------------------------

    return {
        "domain_age": domain_age,
        "domain_registration_length":
            domain_registration_length,
        "google_index": google_index,
        "page_rank": page_rank,
        "web_traffic": web_traffic
    }
