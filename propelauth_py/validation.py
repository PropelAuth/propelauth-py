from urllib.parse import urlparse


def _validate_url(auth_url):
    parsed_url = urlparse(auth_url)
    if parsed_url.scheme != "https":
        raise ValueError("URL must start with https://")
    elif parsed_url.netloc == "":
        raise ValueError("Invalid URL")
    else:
        return "https://" + parsed_url.netloc
