import json
import re
from pathlib import Path

import certstream

# ---------- Load the Israeli brands ----------
BRANDS = json.loads((Path(__file__).parent / "brands.json").read_text())
OFFICIAL_DOMAINS = [d for brand in BRANDS.values() for d in brand["official"]]

# Legitimate services that look suspicious (e.g. Microsoft security proxy)
IGNORED_SUFFIXES = (".mcas.ms",)

# ---------- Generic phishing signals (work for ANY website) ----------
SUSPICIOUS_WORDS = ["login", "signin", "verify", "secure", "account", "update",
                    "payment", "confirm", "wallet", "refund", "invoice",
                    "password", "auth", "billing", "otp", "support"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".online", ".click", ".site", ".live", ".info",
                   ".shop", ".icu", ".buzz", ".cfd", ".sbs", ".rest", ".support"]

seen_count = 0


def is_official(domain):
    return any(domain == d or domain.endswith("." + d) for d in OFFICIAL_DOMAINS)


def contains_keyword(keyword, domain):
    """Long keywords can be anywhere; short ones must be a separate word."""
    if len(keyword) >= 8:
        return keyword in domain
    pattern = rf"(?<![a-z]){re.escape(keyword)}(?![a-z])"
    return re.search(pattern, domain) is not None


def find_brand(domain):
    for brand, info in BRANDS.items():
        if any(contains_keyword(k, domain) for k in info["keywords"]):
            return brand
    return None


def score_domain(domain):
    """Give the domain a suspicion score and the list of reasons."""
    score = 0
    reasons = []

    brand = find_brand(domain)
    if brand:
        score += 60
        reasons.append(f"imitates {brand}")

    # Suspicious words must start a word (so "authority" counts, "inwiauth" does not)
    words = [w for w in SUSPICIOUS_WORDS if re.search(rf"(?<![a-z]){w}", domain)]
    if words:
        score += min(15 * len(words), 60)
        reasons.append("words: " + ", ".join(words))

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        reasons.append("cheap TLD")

    # Do not count the hyphens of "xn--" (normal accented letters)
    if domain.replace("xn--", "").count("-") >= 3:
        score += 10
        reasons.append("many hyphens")

    if domain.count(".") >= 4:
        score += 10
        reasons.append("many subdomains")

    # Special letters are only suspicious together with a brand
    if "xn--" in domain and brand:
        score += 20
        reasons.append("special letters + brand")

    return score, reasons

seen_domains = set()


def on_message(message, context):
    global seen_count
    if message["message_type"] != "certificate_update":
        return

    for domain in message["data"]["leaf_cert"]["all_domains"]:
        seen_count += 1
        domain = domain.lower().lstrip("*.")
        if domain.startswith("www."):
            domain = domain[4:]

        # Each site only once
        if domain in seen_domains or is_official(domain) or domain.endswith(IGNORED_SUFFIXES):
            continue
        seen_domains.add(domain)

        score, reasons = score_domain(domain)
        if score >= 60:
            line = f"{score}\t{domain}\t{'; '.join(reasons)}"
            print(("🚨 " if score >= 80 else "⚠️ ") + line)
            # Save every suspicious site in a file
            with open("suspicious.tsv", "a", encoding="utf-8") as f:
                f.write(line + "\n")

    if seen_count % 50000 < 5:
        print(f"... {seen_count} domains checked")


if __name__ == "__main__":
    print(f"Hunting for fake sites ({len(BRANDS)} Israeli brands loaded)...")
    certstream.listen_for_events(on_message, url="ws://localhost:8080/")