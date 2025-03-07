from urllib.parse import urlparse


def _validate_and_extract_auth_hostname(auth_url):
    parsed_url = urlparse(auth_url)
    
    if parsed_url.netloc == "":
        raise ValueError("Invalid URL")
    else:
        return parsed_url.netloc
