"""Feature extraction for the final Random Forest phishing detector.

This module intentionally extracts ONLY the 25 features selected by the final
model. The formulas mirror the Web Page Phishing Detection dataset extraction
logic as closely as practical for live URLs.

Prediction is NOT performed here. This file only turns a URL/web page into
numeric features for the trained machine-learning model.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup


# ============================================================
# FINAL 25 FEATURES USED BY THE MODEL
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
# SETTINGS
# ============================================================

CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
MAX_REDIRECTS = 5
MAX_HTML_BYTES = 5 * 1024 * 1024  # 5 MB

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Use tldextract's bundled Public Suffix List snapshot instead of doing a live
# update during prediction. This keeps extraction deterministic and fast.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


# ============================================================
# DATASET CONSTANTS
# ============================================================

# Same phishing-hint vocabulary used by the original dataset extractor.
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

# Brand list used by the dataset's domain_in_brand feature.
# Kept inside this file so deployment does not depend on an extra text file.
ALL_BRANDS = set(
    """
accenture
activisionblizzard
adidas
adobe
adultfriendfinder
agriculturalbankofchina
akamai
alibaba
aliexpress
alipay
alliance
alliancedata
allianceone
allianz
alphabet
amazon
