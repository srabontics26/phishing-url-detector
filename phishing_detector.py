from urllib.parse import urlparse


def get_url_features(url):
    parsed = urlparse(url)

    hostname = parsed.netloc

    features = {
        "length": len(url),
        "https": parsed.scheme == "https",
        "has_ip": hostname.replace(".", "").isdigit(),
        "subdomains": hostname.count("."),
        "has_at": "@" in url,
        "has_dash": "-" in hostname
    }

    return features


def check_url(url):
    features = get_url_features(url)
    score = 0

    if features["length"] > 75:
        score += 1

    if not features["https"]:
        score += 1

    if features["has_ip"]:
        score += 2

    if features["subdomains"] > 2:
        score += 1

    if features["has_at"]:
        score += 1

    if features["has_dash"]:
        score += 1

    if score >= 3:
        return "Potentially suspicious", score

    return "Likely legitimate", score


def main():
    print("Phishing URL Detector")
    print("---------------------")

    url = input("Enter a URL: ").strip()

    result, score = check_url(url)

    print("\nResult:", result)
    print("Risk score:", score)


if __name__ == "__main__":
    main()
