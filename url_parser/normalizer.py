from urllib.parse import urlparse, urlunparse


def normalize(url: str):
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()

    netloc = hostname

    if parsed.port:
        netloc += f":{parsed.port}"

    return urlunparse(
        (
            scheme,
            netloc,
            parsed.path.rstrip("/") or "/",
            "",
            parsed.query,
            parsed.fragment,
        )
    )