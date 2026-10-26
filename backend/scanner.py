from urllib.parse import urlparse
import requests


# =========================================================
# CERBERUS WEB APPLICATION SECURITY SCANNER
# OWASP TOP 10 (2025) ASSESSMENT FRAMEWORK
# =========================================================


USER_AGENT = "CERBERUS-Security-Scanner/1.0"


# =========================================================
# BASIC TARGET VALIDATION
# =========================================================

def validate_target(url: str) -> bool:

    parsed = urlparse(url)

    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
    )


def get_response(url: str):

    try:

        return requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

    except requests.RequestException:

        return None


# =========================================================
# A02 - CRYPTOGRAPHIC FAILURES
# =========================================================

def check_https(url: str) -> dict:

    parsed = urlparse(url)

    if parsed.scheme == "https":

        return {
            "id": "WEB-A02-001",
            "owasp": "A02",
            "category": "Cryptographic Failures",
            "check": "HTTPS",
            "status": "pass",
            "severity": "info",
            "description": "The target uses HTTPS.",
            "recommendation": "Continue enforcing HTTPS for sensitive communications."
        }

    return {
        "id": "WEB-A02-001",
        "owasp": "A02",
        "category": "Cryptographic Failures",
        "check": "HTTPS",
        "status": "fail",
        "severity": "medium",
        "description": "The target does not use HTTPS.",
        "recommendation": "Configure HTTPS and redirect HTTP traffic to HTTPS."
    }


# =========================================================
# A05 - SECURITY MISCONFIGURATION
# =========================================================

def check_security_headers(response) -> list:

    if response is None:

        return [{
            "id": "WEB-A05-001",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Security Headers",
            "status": "not_tested",
            "severity": "info",
            "description": "Security headers could not be checked because the target could not be reached.",
            "recommendation": "Verify that the target is available and authorized for assessment."
        }]

    headers = response.headers

    security_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security"
    ]

    findings = []

    for header in security_headers:

        if header in headers:

            findings.append({
                "id": f"WEB-A05-{len(findings) + 2:03d}",
                "owasp": "A05",
                "category": "Security Misconfiguration",
                "check": header,
                "status": "pass",
                "severity": "info",
                "description": f"{header} is present.",
                "recommendation": f"Continue configuring {header} securely."
            })

        else:

            findings.append({
                "id": f"WEB-A05-{len(findings) + 2:03d}",
                "owasp": "A05",
                "category": "Security Misconfiguration",
                "check": header,
                "status": "fail",
                "severity": "low",
                "description": f"{header} is not present.",
                "recommendation": f"Consider configuring {header} appropriately."
            })

    return findings


# =========================================================
# A05 - COOKIE SECURITY
# =========================================================

def check_cookie_security(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A05-006",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "not_tested",
            "severity": "info",
            "description": "Cookies could not be checked.",
            "recommendation": "Verify the target is reachable."
        }

    cookies = response.headers.get("Set-Cookie")

    if not cookies:

        return {
            "id": "WEB-A05-006",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "not_tested",
            "severity": "info",
            "description": "The response did not set a cookie.",
            "recommendation": "If the application uses cookies, ensure Secure, HttpOnly and appropriate SameSite attributes are configured."
        }

    cookie_lower = cookies.lower()

    missing = []

    if "secure" not in cookie_lower:
        missing.append("Secure")

    if "httponly" not in cookie_lower:
        missing.append("HttpOnly")

    if "samesite" not in cookie_lower:
        missing.append("SameSite")

    if missing:

        return {
            "id": "WEB-A05-006",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "review",
            "severity": "medium",
            "description": "One or more recommended cookie security attributes were not observed.",
            "missing_attributes": missing,
            "recommendation": "Review cookie configuration and apply Secure, HttpOnly and appropriate SameSite attributes where applicable."
        }

    return {
        "id": "WEB-A05-006",
        "owasp": "A05",
        "category": "Security Misconfiguration",
        "check": "Cookie Security",
        "status": "pass",
        "severity": "info",
        "description": "Recommended cookie security attributes were observed.",
        "recommendation": "Continue reviewing cookie configuration."
    }


# =========================================================
# A05 - SERVER TECHNOLOGY DISCLOSURE
# =========================================================

def check_information_disclosure(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A05-007",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Information Disclosure",
            "status": "not_tested",
            "severity": "info",
            "description": "Server information could not be checked.",
            "recommendation": "Verify the target is reachable."
        }

    exposed_headers = {}

    for header in [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version"
    ]:

        value = response.headers.get(header)

        if value:

            exposed_headers[header] = value

    if exposed_headers:

        return {
            "id": "WEB-A05-007",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Information Disclosure",
            "status": "review",
            "severity": "low",
            "description": "Technology-identifying response headers were observed.",
            "headers": exposed_headers,
            "recommendation": "Consider minimizing unnecessary technology disclosure in response headers."
        }

    return {
        "id": "WEB-A05-007",
        "owasp": "A05",
        "category": "Security Misconfiguration",
        "check": "Information Disclosure",
        "status": "pass",
        "severity": "info",
        "description": "No common technology-identifying response headers were observed.",
        "recommendation": "Continue minimizing unnecessary information disclosure."
    }


# =========================================================
# A05 - HTTP METHODS
# =========================================================

def check_http_methods(url: str) -> dict:

    try:

        response = requests.options(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        allow_header = response.headers.get(
            "Allow",
            ""
        )

        if allow_header:

            return {
                "id": "WEB-A05-008",
                "owasp": "A05",
                "category": "Security Misconfiguration",
                "check": "HTTP Methods",
                "status": "review",
                "severity": "low",
                "description": f"The server reported allowed HTTP methods: {allow_header}",
                "allowed_methods": allow_header,
                "recommendation": "Ensure only required HTTP methods are enabled."
            }

        return {
            "id": "WEB-A05-008",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "HTTP Methods",
            "status": "not_tested",
            "severity": "info",
            "description": "The server did not provide an Allow header.",
            "recommendation": "Review the application's required HTTP methods."
        }

    except requests.RequestException:

        return {
            "id": "WEB-A05-008",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "HTTP Methods",
            "status": "not_tested",
            "severity": "info",
            "description": "HTTP methods could not be determined.",
            "recommendation": "Review the application's HTTP method configuration."
        }


# =========================================================
# A01 - BROKEN ACCESS CONTROL
# =========================================================

def check_access_control() -> dict:

    return {
        "id": "WEB-A01-001",
        "owasp": "A01",
        "category": "Broken Access Control",
        "check": "Access Control Review",
        "status": "not_tested",
        "severity": "info",
        "description": "Automated access-control verification requires authenticated application-specific test cases.",
        "recommendation": "Configure authorized authenticated test cases to verify role and resource access."
    }


# =========================================================
# A03 - INJECTION
# =========================================================

def check_injection() -> dict:

    return {
        "id": "WEB-A03-001",
        "owasp": "A03",
        "category": "Injection",
        "check": "Injection Risk Review",
        "status": "not_tested",
        "severity": "info",
        "description": "Injection testing requires application-specific input points and controlled test cases.",
        "recommendation": "Identify authorized input parameters and verify validation, parameterization and safe query handling."
    }


# =========================================================
# A04 - INSECURE DESIGN
# =========================================================

def check_insecure_design() -> dict:

    return {
        "id": "WEB-A04-001",
        "owasp": "A04",
        "category": "Insecure Design",
        "check": "Secure Design Review",
        "status": "not_tested",
        "severity": "info",
        "description": "Insecure design requires application-specific business logic and architecture review.",
        "recommendation": "Review security requirements, abuse cases, trust boundaries and business logic."
    }


# =========================================================
# A06 - VULNERABLE AND OUTDATED COMPONENTS
# =========================================================

def check_outdated_components(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A06-001",
            "owasp": "A06",
            "category": "Vulnerable and Outdated Components",
            "check": "Component Exposure",
            "status": "not_tested",
            "severity": "info",
            "description": "Component information could not be evaluated.",
            "recommendation": "Review application dependencies and server software versions."
        }

    return {
        "id": "WEB-A06-001",
        "owasp": "A06",
        "category": "Vulnerable and Outdated Components",
        "check": "Component Exposure",
        "status": "review",
        "severity": "info",
        "description": "A remote HTTP response alone cannot reliably determine whether application components are outdated.",
        "recommendation": "Review dependency versions and compare them with trusted vulnerability databases such as the NVD."
    }


# =========================================================
# A07 - IDENTIFICATION AND AUTHENTICATION FAILURES
# =========================================================

def check_authentication() -> dict:

    return {
        "id": "WEB-A07-001",
        "owasp": "A07",
        "category": "Identification and Authentication Failures",
        "check": "Authentication Review",
        "status": "not_tested",
        "severity": "info",
        "description": "Authentication security requires application-specific login and session testing.",
        "recommendation": "Review password policy, authentication controls, session management, MFA and account protection."
    }


# =========================================================
# A08 - SOFTWARE AND DATA INTEGRITY FAILURES
# =========================================================

def check_integrity() -> dict:

    return {
        "id": "WEB-A08-001",
        "owasp": "A08",
        "category": "Software and Data Integrity Failures",
        "check": "Integrity Controls Review",
        "status": "not_tested",
        "severity": "info",
        "description": "Software and data integrity controls cannot be reliably verified from a basic HTTP request.",
        "recommendation": "Review dependency integrity, trusted update mechanisms, CI/CD controls and signed artifacts."
    }


# =========================================================
# A09 - SECURITY LOGGING AND MONITORING FAILURES
# =========================================================

def check_logging() -> dict:

    return {
        "id": "WEB-A09-001",
        "owasp": "A09",
        "category": "Security Logging and Monitoring Failures",
        "check": "Logging and Monitoring Review",
        "status": "not_tested",
        "severity": "info",
        "description": "Application logging and monitoring cannot be verified from a basic external HTTP request.",
        "recommendation": "Review security event logging, alerting, monitoring and incident response capabilities."
    }


# =========================================================
# A10 - SERVER-SIDE REQUEST FORGERY
# =========================================================

def check_ssrf() -> dict:

    return {
        "id": "WEB-A10-001",
        "owasp": "A10",
        "category": "Server-Side Request Forgery",
        "check": "SSRF Review",
        "status": "not_tested",
        "severity": "info",
        "description": "SSRF verification requires identifying authorized server-side URL fetching functionality.",
        "recommendation": "Review URL-fetching features and enforce allowlists, network restrictions and safe URL validation."
    }


# =========================================================
# MAIN WEB SCANNER
# =========================================================

def scan_target(url: str) -> dict:

    if not validate_target(url):

        return {
            "status": "error",
            "message": "Invalid target URL"
        }

    response = get_response(url)

    findings = []

    # A01
    findings.append(
        check_access_control()
    )

    # A02
    findings.append(
        check_https(url)
    )

    # A03
    findings.append(
        check_injection()
    )

    # A04
    findings.append(
        check_insecure_design()
    )

    # A05
    findings.extend(
        check_security_headers(response)
    )

    findings.append(
        check_cookie_security(response)
    )

    findings.append(
        check_information_disclosure(response)
    )

    findings.append(
        check_http_methods(url)
    )

    # A06
    findings.append(
        check_outdated_components(response)
    )

    # A07
    findings.append(
        check_authentication()
    )

    # A08
    findings.append(
        check_integrity()
    )

    # A09
    findings.append(
        check_logging()
    )

    # A10
    findings.append(
        check_ssrf()
    )

    return {
        "status": "completed",
        "target": url,
        "owasp_version": "OWASP Top 10:2025",
        "findings": findings
    }