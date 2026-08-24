from urllib.parse import unquote
import ipaddress


SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alternative",
}


class SecurityAnalyzer:
    def __init__(self, parser, query=None):
        self.parser = parser
        self.query = query

    @property
    def https(self):
        return self.parser.scheme.lower() == "https"

    @property
    def credentials_exposed(self):
        return bool(
            self.parser.username or
            self.parser.password
        )

    @property
    def ip_address(self):
        return self.parser.is_ip

    @property
    def ip_type(self):
        if not self.parser.is_ip:
            return None

        try:
            ip = ipaddress.ip_address(self.parser.hostname)

            if ip.is_loopback:
                return "Loopback"

            if ip.is_private:
                return "Private"

            if ip.is_link_local:
                return "Link-local"

            if ip.is_reserved:
                return "Reserved"

            return "Public"

        except ValueError:
            return None

    @property
    def localhost(self):
        host = self.parser.hostname.lower()

        return host in {
            "localhost",
            "127.0.0.1",
            "::1",
        }

    @property
    def private_network(self):
        return self.ip_type in {
            "Private",
            "Loopback",
            "Link-local",
        }

    @property
    def suspicious_port(self):
        return SUSPICIOUS_PORTS.get(self.parser.port)

    @property
    def encoded_characters(self):
        return "%" in self.parser.full_url

    @property
    def decoded_url(self):
        return unquote(self.parser.full_url)

    @property
    def suspicious_characters(self):
        suspicious = [
            "\\",
            "<",
            ">",
            '"',
            "'",
            "`",
        ]

        return [
            char
            for char in suspicious
            if char in self.parser.full_url
        ]

    def calculate_score(self):
        score = 0

        if not self.https:
            score += 2

        if self.credentials_exposed:
            score += 3

        if self.ip_address:
            score += 1

        if self.localhost:
            score += 1

        if self.suspicious_port:
            score += 1

        if self.suspicious_characters:
            score += 1

        if self.query:
            if self.query.duplicate_parameters:
                score += 1

        return min(score, 10)

    def risk_level(self):
        score = self.calculate_score()

        if score >= 8:
            return "CRITICAL"

        if score >= 5:
            return "HIGH"

        if score >= 3:
            return "MEDIUM"

        return "LOW"

    def findings(self):
        findings = []

        if not self.https:
            findings.append({
                "severity": "HIGH",
                "title": "HTTPS is not enabled",
                "description": (
                    "The URL uses HTTP instead of HTTPS."
                ),
                "recommendation": (
                    "Use HTTPS to protect data in transit."
                ),
            })

        if self.credentials_exposed:
            findings.append({
                "severity": "CRITICAL",
                "title": "Credentials exposed in URL",
                "description": (
                    "A username or password is embedded "
                    "directly in the URL."
                ),
                "recommendation": (
                    "Never share URLs containing credentials."
                ),
            })

        if self.ip_address:
            findings.append({
                "severity": "MEDIUM",
                "title": "IP address detected",
                "description": (
                    f"The hostname is an IP address "
                    f"({self.ip_type})."
                ),
                "recommendation": (
                    "Verify that direct IP access is intentional."
                ),
            })

        if self.localhost:
            findings.append({
                "severity": "MEDIUM",
                "title": "Localhost detected",
                "description": (
                    "The URL points to the local machine."
                ),
                "recommendation": (
                    "Make sure this URL is not exposed publicly."
                ),
            })

        if self.suspicious_port:
            findings.append({
                "severity": "MEDIUM",
                "title": "Non-standard port detected",
                "description": (
                    f"Port {self.parser.port} "
                    f"is commonly associated with "
                    f"{self.suspicious_port}."
                ),
                "recommendation": (
                    "Verify that this port is expected."
                ),
            })

        if self.query and self.query.duplicate_parameters:
            findings.append({
                "severity": "MEDIUM",
                "title": "Duplicate query parameters",
                "description": (
                    "One or more query parameters appear "
                    "multiple times."
                ),
                "recommendation": (
                    "Verify that duplicate parameters are intentional."
                ),
            })

        if self.suspicious_characters:
            findings.append({
                "severity": "HIGH",
                "title": "Suspicious characters detected",
                "description": (
                    "The URL contains characters that may "
                    "require additional inspection."
                ),
                "recommendation": (
                    "Inspect the URL before processing it."
                ),
            })

        return findings

    def run(self):
        return {
            "https": self.https,
            "credentials": self.credentials_exposed,
            "ip_address": self.ip_address,
            "ip_type": self.ip_type,
            "localhost": self.localhost,
            "private_network": self.private_network,
            "suspicious_port": self.suspicious_port,
            "encoded": self.encoded_characters,
            "suspicious_characters": self.suspicious_characters,
            "risk_score": self.calculate_score(),
            "risk_level": self.risk_level(),
            "findings": self.findings(),
        }