from urllib.parse import urlparse, parse_qsl
import ipaddress


class URLParser:
    def __init__(self, url: str):
        self.original = url.strip()

        if not self.original:
            raise ValueError("URL cannot be empty.")

        if "://" not in self.original:
            self.url = "https://" + self.original
        else:
            self.url = self.original

        try:
            self.parsed = urlparse(self.url)

            if not self.parsed.hostname:
                raise ValueError("Invalid URL.")

        except Exception as error:
            raise ValueError("Invalid URL.") from error

    @property
    def scheme(self):
        return self.parsed.scheme

    @property
    def username(self):
        return self.parsed.username

    @property
    def password(self):
        return self.parsed.password

    @property
    def hostname(self):
        return self.parsed.hostname

    @property
    def port(self):
        try:
            return self.parsed.port
        except ValueError:
            return None

    @property
    def path(self):
        return self.parsed.path or "/"

    @property
    def query(self):
        return self.parsed.query

    @property
    def fragment(self):
        return self.parsed.fragment

    @property
    def origin(self):
        port = self.port

        if port:
            return f"{self.scheme}://{self.hostname}:{port}"

        return f"{self.scheme}://{self.hostname}"

    @property
    def full_url(self):
        return self.url

    @property
    def query_params(self):
        return parse_qsl(
            self.query,
            keep_blank_values=True
        )

    @property
    def is_ip(self):
        try:
            ipaddress.ip_address(self.hostname)
            return True
        except ValueError:
            return False

    @property
    def domain(self):
        if self.is_ip:
            return self.hostname

        parts = self.hostname.split(".")

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return self.hostname

    @property
    def subdomain(self):
        if self.is_ip:
            return None

        parts = self.hostname.split(".")

        if len(parts) > 2:
            return ".".join(parts[:-2])

        return None

    @property
    def tld(self):
        if self.is_ip:
            return None

        parts = self.hostname.split(".")

        return parts[-1] if len(parts) >= 2 else None