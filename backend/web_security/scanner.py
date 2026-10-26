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

    except requests.RequestException as exc:

        print(
            f"[CERBERUS] Request failed: {type(exc).__name__}: {exc}"
        )

        return None


# =========================================================
# A01 - BROKEN ACCESS CONTROL
# =========================================================

def check_access_control(url: str) -> list:

    parsed = urlparse(url)

    base_url = (
        f"{parsed.scheme}://{parsed.netloc}"
    )

    paths = [
        "/admin",
        "/administrator",
        "/dashboard",
        "/manage",
        "/internal",
    ]

    findings = []

    for index, path in enumerate(paths, start=1):

        test_url = base_url + path

        try:

            response = requests.get(
                test_url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            status_code = response.status_code

            if status_code == 200:

                findings.append({
                    "id": f"WEB-A01-{index:03d}",
                    "owasp": "A01",
                    "category": "Broken Access Control",
                    "check": f"Public Access to {path}",
                    "status": "review",
                    "severity": "medium",
                    "description": (
                        f"The path {path} returned HTTP 200 "
                        "without an authentication challenge."
                    ),
                    "evidence": {
                        "url": test_url,
                        "status_code": status_code
                    },
                    "recommendation": (
                        "Verify that this resource is intentionally "
                        "public. Protected resources should require "
                        "authentication and authorization."
                    )
                })

            elif status_code in {401, 403}:

                findings.append({
                    "id": f"WEB-A01-{index:03d}",
                    "owasp": "A01",
                    "category": "Broken Access Control",
                    "check": f"Access Control for {path}",
                    "status": "pass",
                    "severity": "info",
                    "description": (
                        f"The path {path} returned HTTP "
                        f"{status_code}, indicating that access "
                        "restriction is present."
                    ),
                    "evidence": {
                        "url": test_url,
                        "status_code": status_code
                    },
                    "recommendation": (
                        "Continue testing authorization with "
                        "different user roles."
                    )
                })

            elif status_code == 404:

                findings.append({
                    "id": f"WEB-A01-{index:03d}",
                    "owasp": "A01",
                    "category": "Broken Access Control",
                    "check": f"Access Control for {path}",
                    "status": "pass",
                    "severity": "info",
                    "description": (
                        f"The path {path} returned HTTP 404. "
                        "The tested resource was not exposed."
                    ),
                    "evidence": {
                        "url": test_url,
                        "status_code": status_code
                    },
                    "recommendation": (
                        "Continue testing known protected resources "
                        "with authenticated and unauthenticated users."
                    )
                })

            elif 300 <= status_code < 400:

                findings.append({
                    "id": f"WEB-A01-{index:03d}",
                    "owasp": "A01",
                    "category": "Broken Access Control",
                    "check": f"Access Control Redirect for {path}",
                    "status": "review",
                    "severity": "low",
                    "description": (
                        f"The path {path} returned HTTP "
                        f"{status_code}."
                    ),
                    "evidence": {
                        "url": test_url,
                        "status_code": status_code,
                        "location": response.headers.get(
                            "Location",
                            ""
                        )
                    },
                    "recommendation": (
                        "Verify that protected resources redirect "
                        "unauthenticated users appropriately."
                    )
                })

            else:

                findings.append({
                    "id": f"WEB-A01-{index:03d}",
                    "owasp": "A01",
                    "category": "Broken Access Control",
                    "check": f"Access Control for {path}",
                    "status": "review",
                    "severity": "low",
                    "description": (
                        f"The path {path} returned HTTP "
                        f"{status_code}."
                    ),
                    "evidence": {
                        "url": test_url,
                        "status_code": status_code
                    },
                    "recommendation": (
                        "Review the access-control behavior "
                        "of this resource."
                    )
                })

        except requests.RequestException as exc:

            findings.append({
                "id": f"WEB-A01-{index:03d}",
                "owasp": "A01",
                "category": "Broken Access Control",
                "check": f"Access Control for {path}",
                "status": "not_tested",
                "severity": "info",
                "description": (
                    f"The request to {path} could not be completed."
                ),
                "evidence": {
                    "url": test_url,
                    "error": type(exc).__name__
                },
                "recommendation": (
                    "Verify that the target is reachable and "
                    "repeat the access-control test."
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
            "description": (
                "The target could not be reached, so HSTS "
                "could not be checked."
            ),
            "recommendation": (
                "Verify that the target is reachable over HTTPS."
            )
        }

    final_url = response.url

    parsed = urlparse(final_url)

    hsts = response.headers.get(
        "Strict-Transport-Security"
    )

    # HSTS only applies to HTTPS
    if parsed.scheme != "https":

        return {
            "id": "WEB-A02-002",
            "owasp": "A02",
            "category": "Cryptographic Failures",
            "check": "HTTP Strict Transport Security",
            "status": "review",
            "severity": "low",
            "description": (
                "The final response was not served over HTTPS, "
                "so HSTS cannot be meaningfully evaluated."
            ),
            "evidence": {
                "final_url": final_url,
                "hsts_header_present": bool(hsts)
            },
            "recommendation": (
                "Use HTTPS for the application and configure "
                "HSTS on the HTTPS response."
            )
        }

    if not hsts:

        return {
            "id": "WEB-A02-002",
            "owasp": "A02",
            "category": "Cryptographic Failures",
            "check": "HTTP Strict Transport Security",
            "status": "fail",
            "severity": "medium",
            "description": (
                "The HTTPS response does not contain a "
                "Strict-Transport-Security header."
            ),
            "evidence": {
                "final_url": final_url,
                "hsts_header_present": False
            },
            "recommendation": (
                "Configure Strict-Transport-Security with an "
                "appropriate max-age value."
            )
        }

    hsts_lower = hsts.lower()

    max_age_present = "max-age=" in hsts_lower

    if not max_age_present:

        return {
            "id": "WEB-A02-002",
            "owasp": "A02",
            "category": "Cryptographic Failures",
            "check": "HTTP Strict Transport Security",
            "status": "fail",
            "severity": "medium",
            "description": (
                "HSTS is present, but the policy does not "
                "contain a max-age directive."
            ),
            "evidence": {
                "header": hsts
            },
            "recommendation": (
                "Configure HSTS with an appropriate max-age value."
            )
        }

    return {
        "id": "WEB-A02-002",
        "owasp": "A02",
        "category": "Cryptographic Failures",
        "check": "HTTP Strict Transport Security",
        "status": "pass",
        "severity": "info",
        "description": (
            "The HTTPS response contains a valid HSTS "
            "max-age directive."
        ),
        "evidence": {
            "header": hsts,
            "final_url": final_url
        },
        "recommendation": (
            "Continue maintaining a strong HSTS policy."
        )
    }

# =========================================================
# A03 - INJECTION
# =========================================================

def check_injection(url: str, response=None) -> dict:

    from urllib.parse import (
        urlparse,
        parse_qsl,
        urlencode,
        urlunparse
    )

    parsed = urlparse(url)

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True
    )

    # ---------------------------------------------------------
    # No URL parameters
    # ---------------------------------------------------------

    if not parameters:

        if response is not None:

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            if "text/html" in content_type:

                html = response.text.lower()

                input_indicators = [
                    "<form",
                    "<input",
                    "<textarea",
                    "<select"
                ]

                detected = [
                    indicator
                    for indicator in input_indicators
                    if indicator in html
                ]

                if detected:

                    return {
                        "id": "WEB-A03-001",
                        "owasp": "A03",
                        "category": "Injection",
                        "check": "Input Surface Detection",
                        "status": "review",
                        "severity": "medium",
                        "description": (
                            "HTML input controls were detected, "
                            "but no URL query parameters were available "
                            "for the safe reflection test."
                        ),
                        "evidence": {
                            "input_controls": detected
                        },
                        "recommendation": (
                            "Review all user-controlled input and ensure "
                            "parameterized queries and safe APIs are used."
                        )
                    }

        return {
            "id": "WEB-A03-001",
            "owasp": "A03",
            "category": "Injection",
            "check": "Safe Reflection Test",
            "status": "pass",
            "severity": "info",
            "description": (
                "No URL query parameters were found on the scanned "
                "resource, so no query-parameter injection point "
                "was available for the safe reflection test."
            ),
            "evidence": {
                "query_parameters": 0
            },
            "recommendation": (
                "Continue validating all user-controlled input "
                "throughout the application."
            )
        }

    # ---------------------------------------------------------
    # Safe reflection test
    # ---------------------------------------------------------

    parameter_names = [
        name
        for name, value in parameters
    ]

    test_parameter = parameter_names[0]

    marker = "CERBERUS-INJECTION-TEST-9X7"

    test_parameters = []

    replaced = False

    for name, value in parameters:

        if name == test_parameter and not replaced:

            test_parameters.append(
                (name, marker)
            )

            replaced = True

        else:

            test_parameters.append(
                (name, value)
            )

    test_query = urlencode(
        test_parameters,
        doseq=True
    )

    test_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        test_query,
        parsed.fragment
    ))

    try:

        test_response = get_response(
            test_url
        )

    except Exception:

        test_response = None

    if test_response is None:

        return {
            "id": "WEB-A03-001",
            "owasp": "A03",
            "category": "Injection",
            "check": "Safe Reflection Test",
            "status": "not_tested",
            "severity": "medium",
            "description": (
                "The target contains URL parameters, but the "
                "safe reflection test could not be completed."
            ),
            "evidence": {
                "parameters": parameter_names
            },
            "recommendation": (
                "Review the identified parameters for proper "
                "input validation and output encoding."
            )
        }

    response_text = test_response.text

    # ---------------------------------------------------------
    # Exact reflection
    # ---------------------------------------------------------

    if marker in response_text:

        return {
            "id": "WEB-A03-001",
            "owasp": "A03",
            "category": "Injection",
            "check": "Safe Reflection Test",
            "status": "review",
            "severity": "medium",
            "description": (
                "A harmless CERBERUS test marker was reflected "
                "in the real HTTP response. Reflection alone does "
                "not prove an injection vulnerability, but the "
                "parameter should be reviewed for proper validation "
                "and output encoding."
            ),
            "evidence": {
                "parameter": test_parameter,
                "marker_reflected": True,
                "test_url": test_url
            },
            "recommendation": (
                "Validate server-side input and apply context-aware "
                "output encoding. Perform authorized application-specific "
                "injection testing."
            )
        }

    # ---------------------------------------------------------
    # No reflection
    # ---------------------------------------------------------

    return {
        "id": "WEB-A03-001",
        "owasp": "A03",
        "category": "Injection",
        "check": "Safe Reflection Test",
        "status": "pass",
        "severity": "info",
        "description": (
            "URL parameters were detected, but the harmless "
            "CERBERUS test marker was not reflected in the "
            "HTTP response."
        ),
        "evidence": {
            "parameters": parameter_names,
            "tested_parameter": test_parameter,
            "marker_reflected": False
        },
        "recommendation": (
            "Continue using server-side input validation, "
            "parameterized queries and context-aware output encoding."
        )
    }
# =========================================================
# A04 - INSECURE DESIGN
# =========================================================

def check_insecure_design(url: str, response=None) -> dict:

    parsed = urlparse(url)

    base_url = (
        f"{parsed.scheme}://{parsed.netloc}"
    )

    test_paths = [
        "/debug",
        "/test",
        "/dev",
        "/development",
        "/staging"
    ]

    results = []

    # ---------------------------------------------------------
    # Real HTTP checks for common development/test surfaces
    # ---------------------------------------------------------

    for path in test_paths:

        test_url = base_url + path

        try:

            test_response = requests.get(
                test_url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            status_code = test_response.status_code

            results.append({
                "path": path,
                "status_code": status_code
            })

        except requests.RequestException as exc:

            results.append({
                "path": path,
                "status_code": None,
                "error": type(exc).__name__
            })

    # ---------------------------------------------------------
    # Identify potentially exposed development surfaces
    # ---------------------------------------------------------

    exposed = []

    for result in results:

        status_code = result.get(
            "status_code"
        )

        if status_code in {
            200,
            401,
            403
        }:

            exposed.append(result)

    # ---------------------------------------------------------
    # Potential development/debug surface found
    # ---------------------------------------------------------

    if exposed:

        return {
            "id": "WEB-A04-001",
            "owasp": "A04",
            "category": "Insecure Design",
            "check": "Development and Debug Surface Detection",
            "status": "review",
            "severity": "medium",
            "description": (
                "The scanner tested common development, test and "
                "debug paths on the real target. One or more paths "
                "returned an HTTP response that requires review."
            ),
            "evidence": {
                "tested_paths": results,
                "potential_surfaces": exposed
            },
            "recommendation": (
                "Verify that development, staging, testing and "
                "debugging functionality is not unnecessarily exposed "
                "to untrusted users. Review authentication, authorization "
                "and environment separation."
            )
        }

    # ---------------------------------------------------------
    # No exposed development/debug surface detected
    # ---------------------------------------------------------

    return {
        "id": "WEB-A04-001",
        "owasp": "A04",
        "category": "Insecure Design",
        "check": "Development and Debug Surface Detection",
        "status": "pass",
        "severity": "info",
        "description": (
            "The scanner tested common development, test and "
            "debug paths on the real target. No accessible "
            "development or debug surface was detected."
        ),
        "evidence": {
            "tested_paths": results
        },
        "recommendation": (
            "Continue enforcing environment separation and ensure "
            "debugging and development functionality is not exposed "
            "to untrusted users."
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
                "The target could not be reached."
            ),
            "recommendation": (
                "Verify that the target is reachable."
            )
        }]

    headers = response.headers

    security_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    findings = []

    for index, header in enumerate(
        security_headers,
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
                    f"{header} was found in the real "
                    "HTTP response."
                ),
                "evidence": {
                    "header": header,
                    "value": value
                },
                "recommendation": (
                    f"Continue maintaining the {header} "
                    "configuration."
                )
            })

        else:

            findings.append({
                "id": f"WEB-A05-{index:03d}",
                "owasp": "A05",
                "category": "Security Misconfiguration",
                "check": header,
                "status": "review",
                "severity": "low",
                "description": (
                    f"{header} was not found in the real "
                    "HTTP response."
                ),
                "evidence": {
                    "header": header,
                    "present": False
                },
                "recommendation": (
                    f"Review whether {header} is appropriate "
                    "for this application."
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
                "The target response was unavailable."
            ),
            "recommendation": (
                "Verify that the target is reachable."
            )
        }

    try:

        cookie_headers = response.raw.headers.getlist(
            "Set-Cookie"
        )

    except AttributeError:

        cookie_header = response.headers.get(
            "Set-Cookie"
        )

        cookie_headers = (
            [cookie_header]
            if cookie_header
            else []
        )

    if not cookie_headers:

        return {
            "id": "WEB-A05-007",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "pass",
            "severity": "info",
            "description": (
                "The target response did not set cookies."
            ),
            "evidence": {
                "cookies_found": 0
            },
            "recommendation": (
                "If the application uses cookies on other "
                "pages, review their security attributes."
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

        missing = []

        if "Secure" not in attributes:
            missing.append("Secure")

        if "HttpOnly" not in attributes:
            missing.append("HttpOnly")

        if "SameSite" not in attributes:
            missing.append("SameSite")

        cookie_results.append({
            "name": cookie_name,
            "attributes": attributes,
            "missing_attributes": missing
        })

    insecure_cookies = [
        cookie
        for cookie in cookie_results
        if cookie["missing_attributes"]
    ]

    if insecure_cookies:

        return {
            "id": "WEB-A05-007",
            "owasp": "A05",
            "category": "Security Misconfiguration",
            "check": "Cookie Security",
            "status": "review",
            "severity": "medium",
            "description": (
                "The real HTTP response contains cookies "
                "missing one or more recommended security attributes."
            ),
            "evidence": {
                "cookies": cookie_results
            },
            "recommendation": (
                "Review Secure, HttpOnly and SameSite attributes "
                "for authentication and session cookies."
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
            "All observed cookies contain Secure, HttpOnly "
            "and SameSite attributes."
        ),
        "evidence": {
            "cookies": cookie_results
        },
        "recommendation": (
            "Continue maintaining secure cookie configuration."
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
            "check": "Authentication Surface Detection",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "The target response was unavailable, so the "
                "authentication surface could not be inspected."
            ),
            "recommendation": (
                "Verify that the target is reachable and review "
                "authentication and session controls."
            )
        }

    import re

    html = response.text

    html_lower = html.lower()

    detected = []

    # ---------------------------------------------------------
    # Password fields
    # ---------------------------------------------------------

    password_fields = re.findall(
        r'<input[^>]+type\s*=\s*["\']password["\'][^>]*>',
        html,
        re.IGNORECASE
    )

    if password_fields:

        detected.append({
            "type": "password_field",
            "count": len(password_fields)
        })

    # ---------------------------------------------------------
    # Login/authentication forms
    # ---------------------------------------------------------

    authentication_keywords = [
        "login",
        "signin",
        "sign-in",
        "authenticate",
        "authentication",
        "account"
    ]

    detected_keywords = []

    for keyword in authentication_keywords:

        if keyword in html_lower:

            detected_keywords.append(keyword)

    if detected_keywords:

        detected.append({
            "type": "authentication_indicators",
            "values": detected_keywords
        })

    # ---------------------------------------------------------
    # Username/email fields
    # ---------------------------------------------------------

    username_fields = re.findall(
        r'<input[^>]+(?:name|id)\s*=\s*["\'][^"\']*'
        r'(?:username|user|email)[^"\']*["\'][^>]*>',
        html,
        re.IGNORECASE
    )

    if username_fields:

        detected.append({
            "type": "username_or_email_field",
            "count": len(username_fields)
        })

    # ---------------------------------------------------------
    # Authentication/session cookies
    # ---------------------------------------------------------

    try:

        cookie_headers = response.raw.headers.getlist(
            "Set-Cookie"
        )

    except AttributeError:

        cookie_header = response.headers.get(
            "Set-Cookie"
        )

        cookie_headers = (
            [cookie_header]
            if cookie_header
            else []
        )

    session_cookie_names = []

    for cookie in cookie_headers:

        cookie_name = cookie.split(
            "=",
            1
        )[0].strip().lower()

        session_keywords = [
            "session",
            "sess",
            "auth",
            "token",
            "jwt",
            "login"
        ]

        if any(
            keyword in cookie_name
            for keyword in session_keywords
        ):

            session_cookie_names.append(
                cookie_name
            )

    if session_cookie_names:

        detected.append({
            "type": "authentication_cookie",
            "cookies": session_cookie_names
        })

    # ---------------------------------------------------------
    # Result
    # ---------------------------------------------------------

    if detected:

        return {
            "id": "WEB-A07-001",
            "owasp": "A07",
            "category": "Identification and Authentication Failures",
            "check": "Authentication Surface Detection",
            "status": "review",
            "severity": "medium",
            "description": (
                "Authentication-related elements were detected "
                "in the real HTTP response. This confirms an "
                "authentication surface exists, but does not "
                "prove that authentication is vulnerable."
            ),
            "evidence": {
                "detected": detected,
                "final_url": response.url
            },
            "recommendation": (
                "Review password protection, MFA, session "
                "management, account lockout, credential "
                "protection and authentication rate limiting."
            )
        }

    return {
        "id": "WEB-A07-001",
        "owasp": "A07",
        "category": "Identification and Authentication Failures",
        "check": "Authentication Surface Detection",
        "status": "pass",
        "severity": "info",
        "description": (
            "No obvious authentication form, password field "
            "or authentication session cookie was detected "
            "in the scanned page."
        ),
        "evidence": {
            "authentication_surface_detected": False,
            "final_url": response.url
        },
        "recommendation": (
            "If authentication exists on other application "
            "pages, review those authentication and session "
            "controls separately."
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
            "check": "Subresource Integrity",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "The target webpage could not be reached."
            ),
            "recommendation": (
                "Verify that the target is reachable."
            )
        }

    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    if "text/html" not in content_type:

        return {
            "id": "WEB-A08-001",
            "owasp": "A08",
            "category": "Software and Data Integrity Failures",
            "check": "Subresource Integrity",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "The target response is not an HTML document, "
                "so external HTML resources could not be inspected."
            ),
            "recommendation": (
                "Review integrity protection for externally loaded "
                "JavaScript and CSS resources."
            )
        }

    html = response.text

    import re

    resources = []

    # External JavaScript files
    script_pattern = re.compile(
        r"<script\b[^>]*src=[\"']([^\"']+)[\"'][^>]*>",
        re.IGNORECASE
    )

    # External CSS files
    css_pattern = re.compile(
        r"<link\b[^>]*href=[\"']([^\"']+\.css[^\"']*)[\"'][^>]*>",
        re.IGNORECASE
    )

    for match in script_pattern.finditer(html):

        tag = match.group(0)

        src = match.group(1)

        if src.startswith(("http://", "https://", "//")):

            has_integrity = re.search(
                r"\bintegrity\s*=",
                tag,
                re.IGNORECASE
            )

            resources.append({
                "type": "script",
                "url": src,
                "integrity": bool(has_integrity)
            })

    for match in css_pattern.finditer(html):

        tag = match.group(0)

        href = match.group(1)

        if href.startswith(("http://", "https://", "//")):

            has_integrity = re.search(
                r"\bintegrity\s*=",
                tag,
                re.IGNORECASE
            )

            resources.append({
                "type": "stylesheet",
                "url": href,
                "integrity": bool(has_integrity)
            })

    if not resources:

        return {
            "id": "WEB-A08-001",
            "owasp": "A08",
            "category": "Software and Data Integrity Failures",
            "check": "Subresource Integrity",
            "status": "not_tested",
            "severity": "info",
            "description": (
                "No external JavaScript or CSS resources "
                "were detected on the scanned page."
            ),
            "evidence": {
                "external_resources": 0
            },
            "recommendation": (
                "If external resources are used, consider "
                "Subresource Integrity for trusted static resources."
            )
        }

    missing_integrity = [
        resource
        for resource in resources
        if not resource["integrity"]
    ]

    if missing_integrity:

        return {
            "id": "WEB-A08-001",
            "owasp": "A08",
            "category": "Software and Data Integrity Failures",
            "check": "Subresource Integrity",
            "status": "review",
            "severity": "medium",
            "description": (
                "One or more external JavaScript or CSS resources "
                "do not specify an integrity attribute."
            ),
            "evidence": {
                "total_external_resources": len(resources),
                "resources_without_integrity": missing_integrity
            },
            "recommendation": (
                "Consider using Subresource Integrity for external "
                "static resources where appropriate."
            )
        }

    return {
        "id": "WEB-A08-001",
        "owasp": "A08",
        "category": "Software and Data Integrity Failures",
        "check": "Subresource Integrity",
        "status": "pass",
        "severity": "info",
        "description": (
            "All detected external JavaScript and CSS resources "
            "contain integrity attributes."
        ),
        "evidence": {
            "total_external_resources": len(resources),
            "resources": resources
        },
        "recommendation": (
            "Continue maintaining integrity protection "
            "for externally loaded resources."
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