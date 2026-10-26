from urllib.parse import urlparse
import requests


# =========================================================
# CERBERUS WEB APPLICATION SECURITY SCANNER
# OWASP TOP 10 ASSESSMENT
# =========================================================

USER_AGENT = "CERBERUS-Security-Scanner/1.0"


# =========================================================
# BASIC REQUEST FUNCTIONS
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
# A01 - BROKEN ACCESS CONTROL
# =========================================================

def check_access_control(url: str) -> list:

    paths = [
        "/admin",
        "/administrator",
        "/dashboard",
        "/manage",
        "/internal",
    ]

    findings = []

    for index, path in enumerate(paths, start=1):

        test_url = url.rstrip("/") + path

        try:

            response = requests.get(
                test_url,
                timeout=5,
                allow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            if response.status_code == 200:

                findings.append({
                    "id": f"WEB-A01-{index:03d}",
                    "owasp": "A01",
                    "category": "Broken Access Control",
                    "check": f"Public Access to {path}",
                    "status": "review",
                    "severity": "medium",
                    "description": (
                        f"The path {path} returned HTTP 200 "
                        "without authentication."
                    ),
                    "evidence": {
                        "url": test_url,
                        "status_code": response.status_code
                    },
                    "recommendation": (
                        "Verify that this resource is intentionally "
                        "public. Protected administrative or internal "
                        "resources should require proper authentication "
                        "and authorization."
                    )
                })

            elif response.status_code in {401, 403}:

                findings.append({
                    "id": f"WEB-A01-{index:03d}",
                    "owasp": "A01",
                    "category": "Broken Access Control",
                    "check": f"Access Control for {path}",
                    "status": "pass",
                    "severity": "info",
                    "description": (
                        f"The path {path} returned HTTP "
                        f"{response.status_code}, indicating that "
                        "access restrictions are present."
                    ),
                    "evidence": {
                        "url": test_url,
                        "status_code": response.status_code
                    },
                    "recommendation": (
                        "Continue verifying authorization controls "
                        "for different user roles."
                    )
                })

        except requests.RequestException:

            continue

    if not findings:

        findings.append({
            "id": "WEB-A01-006",
            "owasp": "A01",
            "category": "Broken Access Control",
            "check": "Access Control Review",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "No common administrative paths were confirmed "
                "as publicly accessible."
            ),
            "recommendation": (
                "Perform authenticated role-based testing to verify "
                "that users can access only resources permitted "
                "to their roles."
            )
        })

    return findings


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
            "description": (
                "The target uses HTTPS for communication."
            ),
            "evidence": {
                "scheme": parsed.scheme
            },
            "recommendation": (
                "Continue enforcing HTTPS for all sensitive "
                "communications."
            )
        }

    return {
        "id": "WEB-A02-001",
        "owasp": "A02",
        "category": "Cryptographic Failures",
        "check": "HTTPS",
        "status": "fail",
        "severity": "medium",
        "description": (
            "The target URL uses HTTP instead of HTTPS."
        ),
        "evidence": {
            "scheme": parsed.scheme
        },
        "recommendation": (
            "Configure HTTPS and redirect HTTP traffic "
            "to HTTPS."
        )
    }


def check_hsts(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A02-002",
            "owasp": "A02",
            "category": "Cryptographic Failures",
            "check": "HTTP Strict Transport Security",
            "status": "not_tested",
            "severity": "info",
            "description": "HSTS could not be checked.",
            "recommendation": (
                "Verify that the target is reachable."
            )
        }

    hsts = response.headers.get(
        "Strict-Transport-Security"
    )

    if not hsts:

        return {
            "id": "WEB-A02-002",
            "owasp": "A02",
            "category": "Cryptographic Failures",
            "check": "HTTP Strict Transport Security",
            "status": "review",
            "severity": "low",
            "description": (
                "Strict-Transport-Security was not observed "
                "in the response."
            ),
            "recommendation": (
                "For HTTPS applications, configure HSTS with "
                "an appropriate max-age value."
            )
        }

    hsts_lower = hsts.lower()

    max_age_present = "max-age" in hsts_lower

    include_subdomains_present = (
        "includesubdomains" in hsts_lower
    )

    return {
        "id": "WEB-A02-002",
        "owasp": "A02",
        "category": "Cryptographic Failures",
        "check": "HTTP Strict Transport Security",
        "status": "pass",
        "severity": "info",
        "description": (
            "Strict-Transport-Security is present."
        ),
        "evidence": {
            "header": hsts,
            "max_age_present": max_age_present,
            "include_subdomains_present": (
                include_subdomains_present
            )
        },
        "recommendation": (
            "Continue reviewing HSTS configuration and "
            "ensure the policy is appropriate for the application."
        )
    }


# =========================================================
# A03 - INJECTION
# =========================================================

def check_injection(url: str, response) -> dict:

    if response is None:

        return {
            "id": "WEB-A03-001",
            "owasp": "A03",
            "category": "Injection",
            "check": "Injection Risk Review",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "The target could not be reached for injection review."
            ),
            "recommendation": (
                "Verify that the target is reachable and review "
                "application input handling."
            )
        }

    parsed = urlparse(url)

    query_parameters = [
        parameter
        for parameter in parsed.query.split("&")
        if "=" in parameter
    ]

    form_indicators = [
        "<form",
        "input",
        "textarea",
        "select"
    ]

    response_text = response.text.lower()

    detected_indicators = []

    for indicator in form_indicators:

        if indicator in response_text:

            detected_indicators.append(indicator)

    if query_parameters or detected_indicators:

        return {
            "id": "WEB-A03-001",
            "owasp": "A03",
            "category": "Injection",
            "check": "Input Point Detection",
            "status": "review",
            "severity": "medium",
            "description": (
                "Potential application input points were observed. "
                "This does not confirm an injection vulnerability."
            ),
            "evidence": {
                "query_parameters_detected": len(query_parameters),
                "form_indicators_detected": detected_indicators
            },
            "recommendation": (
                "Review all user-controlled input and use parameterized "
                "queries, strict input validation, output encoding and "
                "safe command execution."
            )
        }

    return {
        "id": "WEB-A03-001",
        "owasp": "A03",
        "category": "Injection",
        "check": "Input Point Detection",
        "status": "review",
        "severity": "info",
        "description": (
            "No obvious input points were identified from the "
            "initial response. This does not prove that injection "
            "vulnerabilities are absent."
        ),
        "recommendation": (
            "Perform authorized application-specific testing of "
            "query parameters, forms, headers and API inputs."
        )
    }


# =========================================================
# A04 - INSECURE DESIGN
# =========================================================

def check_insecure_design(url: str, response) -> dict:

    if response is None:

        return {
            "id": "WEB-A04-001",
            "owasp": "A04",
            "category": "Insecure Design",
            "check": "Secure Design Review",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "The target could not be reached for a basic "
                "secure design review."
            ),
            "recommendation": (
                "Review business logic, trust boundaries, abuse cases "
                "and security requirements."
            )
        }

    response_text = response.text.lower()

    risk_indicators = [
        "debug=true",
        "debug=1",
        "test=true",
        "test=1",
        "development",
        "staging",
        "internal",
        "admin"
    ]

    detected_indicators = []

    for indicator in risk_indicators:

        if indicator in response_text:

            detected_indicators.append(indicator)

    if detected_indicators:

        return {
            "id": "WEB-A04-001",
            "owasp": "A04",
            "category": "Insecure Design",
            "check": "Design Risk Indicators",
            "status": "review",
            "severity": "medium",
            "description": (
                "Potential design or environment indicators "
                "were observed in the application response. "
                "This does not confirm an insecure design."
            ),
            "evidence": {
                "indicators": detected_indicators
            },
            "recommendation": (
                "Review business logic, environment separation, "
                "trust boundaries, abuse cases and security "
                "requirements."
            )
        }

    return {
        "id": "WEB-A04-001",
        "owasp": "A04",
        "category": "Insecure Design",
        "check": "Secure Design Review",
        "status": "review",
        "severity": "info",
        "description": (
            "No obvious insecure-design indicators were identified "
            "from the initial HTTP response. This does not prove "
            "that the application has a secure design."
        ),
        "recommendation": (
            "Perform application-specific review of business logic, "
            "trust boundaries, abuse cases and security requirements."
        )
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
            "description": (
                "Security headers could not be checked because "
                "the target response was unavailable."
            ),
            "recommendation": (
                "Verify that the target is reachable and "
                "review its security headers."
            )
        }]

    headers = response.headers

    required_headers = [
        (
            "Content-Security-Policy",
            "low"
        ),
        (
            "X-Content-Type-Options",
            "low"
        ),
        (
            "X-Frame-Options",
            "low"
        ),
        (
            "Strict-Transport-Security",
            "low"
        ),
        (
            "Referrer-Policy",
            "low"
        ),
        (
            "Permissions-Policy",
            "low"
        )
    ]

    findings = []

    for index, (header, severity) in enumerate(
        required_headers,
        start=1
    ):

        value = headers.get(header)

        if value:

            findings.append({
                "id": f"WEB-A05-{index:03d}",
                "owasp": "A05",
                "category": "Security Misconfiguration",
                "check": header,
                "status": "pass",
                "severity": "info",
                "description": (
                    f"{header} is present in the response."
                ),
                "evidence": {
                    "header": header,
                    "value": value
                },
                "recommendation": (
                    f"Continue reviewing the {header} "
                    "configuration for security."
                )
            })

        else:

            findings.append({
                "id": f"WEB-A05-{index:03d}",
                "owasp": "A05",
                "category": "Security Misconfiguration",
                "check": header,
                "status": "review",
                "severity": severity,
                "description": (
                    f"{header} was not observed in the response."
                ),
                "evidence": {
                    "header": header,
                    "present": False
                },
                "recommendation": (
                    f"Review whether {header} should be "
                    "configured for this application."
                )
            })

    return findings


# =========================================================
# A05 - COOKIE SECURITY
# =========================================================

def check_cookie_security(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A05-007",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "Cookies could not be checked because "
                "the target response was unavailable."
            ),
            "recommendation": (
                "Verify that the target is reachable and "
                "review cookie security."
            )
        }

    cookie_headers = response.raw.headers.getlist(
        "Set-Cookie"
    )

    if not cookie_headers:

        return {
            "id": "WEB-A05-007",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "The response did not set any cookies."
            ),
            "recommendation": (
                "If the application uses cookies, review "
                "Secure, HttpOnly and SameSite attributes."
            )
        }

    cookie_results = []

    for cookie in cookie_headers:

        parts = [
            part.strip()
            for part in cookie.split(";")
        ]

        cookie_name = (
            parts[0].split("=", 1)[0]
            if "=" in parts[0]
            else "unknown"
        )

        attributes = []

        for attribute in parts[1:]:

            attribute_name = (
                attribute.split("=", 1)[0]
                .strip()
                .lower()
            )

            if attribute_name == "secure":
                attributes.append("Secure")

            elif attribute_name == "httponly":
                attributes.append("HttpOnly")

            elif attribute_name == "samesite":
                attributes.append("SameSite")

        cookie_results.append({
            "name": cookie_name,
            "attributes": attributes
        })

    missing_attributes = set()

    for cookie in cookie_results:

        if "Secure" not in cookie["attributes"]:
            missing_attributes.add("Secure")

        if "HttpOnly" not in cookie["attributes"]:
            missing_attributes.add("HttpOnly")

        if "SameSite" not in cookie["attributes"]:
            missing_attributes.add("SameSite")

    if missing_attributes:

        return {
            "id": "WEB-A05-007",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "review",
            "severity": "medium",
            "description": (
                "One or more cookies are missing recommended "
                "security attributes."
            ),
            "evidence": {
                "cookies": cookie_results,
                "missing_attributes": sorted(
                    missing_attributes
                )
            },
            "recommendation": (
                "Review cookie configuration and apply "
                "Secure, HttpOnly and SameSite attributes "
                "where appropriate."
            )
        }

    return {
        "id": "WEB-A05-007",
        "owasp": "A05",
        "category": "Security Misconfiguration",
        "check": "Cookie Security",
        "status": "pass",
        "severity": "info",
        "description": (
            "The observed cookies contain Secure, HttpOnly "
            "and SameSite attributes."
        ),
        "evidence": {
            "cookies": cookie_results
        },
        "recommendation": (
            "Continue reviewing cookie configuration "
            "according to the application's security requirements."
        )
    }

# =========================================================
# A05 - INFORMATION DISCLOSURE
# =========================================================

def check_information_disclosure(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A05-008",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Information Disclosure",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "Server information could not be checked "
                "because the target response was unavailable."
            ),
            "recommendation": (
                "Verify that the target is reachable."
            )
        }

    exposed_headers = {}

    headers_to_check = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version"
    ]

    for header in headers_to_check:

        value = response.headers.get(header)

        if value:

            exposed_headers[header] = value

    if exposed_headers:

        return {
            "id": "WEB-A05-008",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Information Disclosure",
            "status": "review",
            "severity": "low",
            "description": (
                "Technology-identifying response headers "
                "were observed."
            ),
            "evidence": {
                "exposed_headers": exposed_headers
            },
            "recommendation": (
                "Consider minimizing unnecessary technology "
                "disclosure in response headers."
            )
        }

    return {
        "id": "WEB-A05-008",
        "owasp": "A05",
        "category": "Security Misconfiguration",
        "check": "Information Disclosure",
        "status": "pass",
        "severity": "info",
        "description": (
            "No common technology-identifying response "
            "headers were observed."
        ),
        "evidence": {
            "checked_headers": headers_to_check
        },
        "recommendation": (
            "Continue minimizing unnecessary information "
            "disclosure."
        )
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

            allowed_methods = [
                method.strip().upper()
                for method in allow_header.split(",")
                if method.strip()
            ]

            dangerous_methods = [
                method
                for method in allowed_methods
                if method in {
                    "TRACE",
                    "CONNECT"
                }
            ]

            if dangerous_methods:

                return {
                    "id": "WEB-A05-009",
                    "owasp": "A05",
                    "category": "Security Misconfiguration",
                    "check": "HTTP Methods",
                    "status": "review",
                    "severity": "medium",
                    "description": (
                        "Potentially dangerous HTTP methods "
                        "were reported by the server."
                    ),
                    "evidence": {
                        "allowed_methods": allowed_methods,
                        "dangerous_methods": dangerous_methods
                    },
                    "recommendation": (
                        "Disable HTTP methods that are not required "
                        "by the application, especially TRACE and "
                        "CONNECT where they are unnecessary."
                    )
                }

            return {
                "id": "WEB-A05-009",
                "owasp": "A05",
                "category": "Security Misconfiguration",
                "check": "HTTP Methods",
                "status": "pass",
                "severity": "info",
                "description": (
                    "The server reported its allowed HTTP methods "
                    "without identifying TRACE or CONNECT."
                ),
                "evidence": {
                    "allowed_methods": allowed_methods
                },
                "recommendation": (
                    "Continue allowing only HTTP methods required "
                    "by the application."
                )
            }

        return {
            "id": "WEB-A05-009",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "HTTP Methods",
            "status": "review",
            "severity": "info",
            "description": (
                "The server did not provide an Allow header, "
                "so the supported HTTP methods could not be "
                "fully determined."
            ),
            "recommendation": (
                "Review the application's HTTP method configuration "
                "and disable unnecessary methods."
            )
        }

    except requests.RequestException:

        return {
            "id": "WEB-A05-009",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "HTTP Methods",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "HTTP methods could not be determined because "
                "the OPTIONS request failed."
            ),
            "recommendation": (
                "Verify that the target is reachable and "
                "review its HTTP method configuration."
            )
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
            "description": (
                "Component information could not be evaluated "
                "because the target response was unavailable."
            ),
            "recommendation": (
                "Review application dependencies, libraries "
                "and server software versions."
            )
        }

    detected_components = {}

    server = response.headers.get("Server")

    powered_by = response.headers.get("X-Powered-By")

    if server:
        detected_components["Server"] = server

    if powered_by:
        detected_components["X-Powered-By"] = powered_by

    if detected_components:

        return {
            "id": "WEB-A06-001",
            "owasp": "A06",
            "category": "Vulnerable and Outdated Components",
            "check": "Component Exposure",
            "status": "review",
            "severity": "low",
            "description": (
                "Technology or server information was exposed "
                "in response headers. This does not confirm "
                "that the component is vulnerable or outdated."
            ),
            "evidence": {
                "detected_components": detected_components
            },
            "recommendation": (
                "Review detected technologies and their versions "
                "against trusted vulnerability databases. "
                "Keep dependencies and server software updated."
            )
        }

    return {
        "id": "WEB-A06-001",
        "owasp": "A06",
        "category": "Vulnerable and Outdated Components",
        "check": "Component Exposure",
        "status": "review",
        "severity": "info",
        "description": (
            "No common technology-identifying response headers "
            "were observed. This does not prove that components "
            "are current or free from vulnerabilities."
        ),
        "evidence": {
            "checked_headers": [
                "Server",
                "X-Powered-By"
            ]
        },
        "recommendation": (
            "Review application dependencies and server software "
            "versions against trusted vulnerability databases."
        )
    }


# =========================================================
# A07 - IDENTIFICATION AND AUTHENTICATION FAILURES
# =========================================================

def check_authentication(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A07-001",
            "owasp": "A07",
            "category": "Identification and Authentication Failures",
            "check": "Authentication Review",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "Authentication controls could not be reviewed "
                "because the target response was unavailable."
            ),
            "recommendation": (
                "Review authentication, session management, "
                "password policies and MFA."
            )
        }

    response_text = response.text.lower()

    authentication_indicators = [
        "login",
        "sign in",
        "signin",
        "authentication",
        "password",
        "username"
    ]

    detected_indicators = []

    for indicator in authentication_indicators:

        if indicator in response_text:

            detected_indicators.append(indicator)

    if detected_indicators:

        return {
            "id": "WEB-A07-001",
            "owasp": "A07",
            "category": "Identification and Authentication Failures",
            "check": "Authentication Indicators",
            "status": "review",
            "severity": "medium",
            "description": (
                "Authentication-related indicators were observed "
                "in the target response. This does not confirm an "
                "authentication vulnerability."
            ),
            "evidence": {
                "detected_indicators": detected_indicators
            },
            "recommendation": (
                "Review authentication controls, password policies, "
                "MFA, session management, account lockout and "
                "protection against credential attacks."
            )
        }

    return {
        "id": "WEB-A07-001",
        "owasp": "A07",
        "category": "Identification and Authentication Failures",
        "check": "Authentication Review",
        "status": "review",
        "severity": "info",
        "description": (
            "No obvious authentication indicators were identified "
            "in the initial response. This does not prove that "
            "authentication controls are secure."
        ),
        "recommendation": (
            "Perform authorized application-specific testing of "
            "authentication, session management, MFA and account "
            "protection controls."
        )
    }


# =========================================================
# A08 - SOFTWARE AND DATA INTEGRITY FAILURES
# =========================================================

def check_integrity(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A08-001",
            "owasp": "A08",
            "category": "Software and Data Integrity Failures",
            "check": "Integrity Controls Review",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "Integrity controls could not be reviewed "
                "because the target response was unavailable."
            ),
            "recommendation": (
                "Review dependency integrity, trusted update "
                "mechanisms, CI/CD controls and signed artifacts."
            )
        }

    headers = response.headers

    integrity_indicators = []

    if headers.get("Content-Security-Policy"):
        integrity_indicators.append(
            "Content-Security-Policy"
        )

    if headers.get("Strict-Transport-Security"):
        integrity_indicators.append(
            "Strict-Transport-Security"
        )

    if headers.get("ETag"):
        integrity_indicators.append(
            "ETag"
        )

    if integrity_indicators:

        return {
            "id": "WEB-A08-001",
            "owasp": "A08",
            "category": "Software and Data Integrity Failures",
            "check": "Integrity Control Indicators",
            "status": "review",
            "severity": "info",
            "description": (
                "Some security-related integrity indicators "
                "were observed. Their presence does not prove "
                "that software and data integrity is fully protected."
            ),
            "evidence": {
                "detected_indicators": integrity_indicators
            },
            "recommendation": (
                "Review dependency integrity, trusted update "
                "mechanisms, CI/CD security, signed artifacts "
                "and protection of sensitive data."
            )
        }

    return {
        "id": "WEB-A08-001",
        "owasp": "A08",
        "category": "Software and Data Integrity Failures",
        "check": "Integrity Controls Review",
        "status": "review",
        "severity": "info",
        "description": (
            "No common integrity indicators were observed "
            "in the initial response. This does not prove "
            "that integrity controls are absent or insecure."
        ),
        "recommendation": (
            "Review dependency integrity, software updates, "
            "CI/CD pipelines, signed artifacts and data integrity "
            "controls."
        )
    }


# =========================================================
# A09 - SECURITY LOGGING AND MONITORING FAILURES
# =========================================================

def check_logging(response) -> dict:

    if response is None:

        return {
            "id": "WEB-A09-001",
            "owasp": "A09",
            "category": "Security Logging and Monitoring Failures",
            "check": "Logging and Monitoring Review",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "Logging and monitoring controls could not be "
                "reviewed because the target response was unavailable."
            ),
            "recommendation": (
                "Review application security logging, monitoring, "
                "alerting and incident response capabilities."
            )
        }

    security_related_headers = []

    if response.headers.get("Content-Security-Policy"):
        security_related_headers.append(
            "Content-Security-Policy"
        )

    if response.headers.get("Strict-Transport-Security"):
        security_related_headers.append(
            "Strict-Transport-Security"
        )

    return {
        "id": "WEB-A09-001",
        "owasp": "A09",
        "category": "Security Logging and Monitoring Failures",
        "check": "Logging and Monitoring Review",
        "status": "review",
        "severity": "info",
        "description": (
            "Application logging and security monitoring cannot "
            "be reliably verified from an external HTTP response."
        ),
        "evidence": {
            "security_headers_observed": security_related_headers
        },
        "recommendation": (
            "Verify that authentication events, authorization "
            "failures, suspicious activity and security events "
            "are logged, monitored and connected to an alerting "
            "and incident response process."
        )
    }


# =========================================================
# A10 - SERVER-SIDE REQUEST FORGERY
# =========================================================

def check_ssrf(url: str, response) -> dict:

    if response is None:

        return {
            "id": "WEB-A10-001",
            "owasp": "A10",
            "category": "Server-Side Request Forgery",
            "check": "SSRF Review",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "SSRF indicators could not be reviewed because "
                "the target response was unavailable."
            ),
            "recommendation": (
                "Identify server-side URL fetching features and "
                "review their URL validation and network restrictions."
            )
        }

    parsed = urlparse(url)

    query_parameters = []

    if parsed.query:

        for parameter in parsed.query.split("&"):

            if "=" in parameter:

                name = parameter.split("=", 1)[0].lower()

                query_parameters.append(name)

    url_related_parameters = [
        parameter
        for parameter in query_parameters
        if any(
            keyword in parameter
            for keyword in [
                "url",
                "uri",
                "link",
                "redirect",
                "callback",
                "return",
                "next",
                "target",
                "dest"
            ]
        )
    ]

    if url_related_parameters:

        return {
            "id": "WEB-A10-001",
            "owasp": "A10",
            "category": "Server-Side Request Forgery",
            "check": "Potential URL Input",
            "status": "review",
            "severity": "medium",
            "description": (
                "URL-related input parameters were observed. "
                "This may indicate functionality that accepts "
                "user-controlled URLs, but it does not confirm "
                "an SSRF vulnerability."
            ),
            "evidence": {
                "parameters": url_related_parameters
            },
            "recommendation": (
                "Review server-side URL fetching functionality. "
                "Use strict allowlists, validate schemes and "
                "destinations, block access to internal networks "
                "and protect cloud metadata endpoints."
            )
        }

    return {
        "id": "WEB-A10-001",
        "owasp": "A10",
        "category": "Server-Side Request Forgery",
        "check": "SSRF Review",
        "status": "review",
        "severity": "info",
        "description": (
            "No obvious URL-related input parameters were "
            "identified in the target URL. This does not prove "
            "that SSRF vulnerabilities are absent."
        ),
        "evidence": {
            "query_parameters": query_parameters
        },
        "recommendation": (
            "Review application features that fetch remote "
            "resources and enforce strict destination validation."
        )
    }


# =========================================================
# MAIN SCANNER
# =========================================================

def scan_target(url: str) -> dict:

    if not validate_target(url):

        return {
            "status": "error",
            "message": "Invalid target URL"
        }

    response = get_response(url)

    findings = []

    # =====================================================
    # A01 - BROKEN ACCESS CONTROL
    # =====================================================

    findings.extend(
        check_access_control(url)
    )

    # =====================================================
    # A02 - CRYPTOGRAPHIC FAILURES
    # =====================================================

    findings.append(
        check_https(url)
    )

    findings.append(
        check_hsts(response)
    )

    # =====================================================
    # A03 - INJECTION
    # =====================================================

    findings.append(
    check_injection(url, response)
)

    # =====================================================
    # A04 - INSECURE DESIGN
    # =====================================================

    findings.append(
    check_insecure_design(url, response)
)

    # =====================================================
    # A05 - SECURITY MISCONFIGURATION
    # =====================================================

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

    # =====================================================
    # A06 - VULNERABLE AND OUTDATED COMPONENTS
    # =====================================================

    findings.append(
        check_outdated_components(response)
    )

    # =====================================================
    # A07 - IDENTIFICATION AND AUTHENTICATION FAILURES
    # =====================================================

    findings.append(
    check_authentication(response)
)

    # =====================================================
    # A08 - SOFTWARE AND DATA INTEGRITY FAILURES
    # =====================================================

    findings.append(
    check_integrity(response)
)

    # =====================================================
    # A09 - SECURITY LOGGING AND MONITORING FAILURES
    # =====================================================

    findings.append(
    check_logging(response)
)

    # =====================================================
    # A10 - SERVER-SIDE REQUEST FORGERY
    # =====================================================

    findings.append(
    check_ssrf(url, response)
)

    return {
        "status": "completed",
        "target": url,
        "findings": findings
    }