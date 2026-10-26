"""CERBERUS API Security Scanner - Demo Version."""

from urllib.parse import urlparse
import requests

USER_AGENT = "CERBERUS-Security-Scanner/3.0"
TIMEOUT = 10

SUPPORTED_METHODS = {
    "get", "post", "put", "patch",
    "delete", "options", "head", "trace"
}


def validate_target(url):
    if not isinstance(url, str) or not url.strip():
        return False

    parsed = urlparse(url.strip())
    return parsed.scheme in ("http", "https") and bool(parsed.hostname)


def result(
    finding_id,
    check,
    status,
    severity,
    description,
    recommendation,
    **extra
):
    item = {
        "id": finding_id,
        "check": check,
        "status": status,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
    }
    item.update(extra)
    return item


def get_response(url):
    if not validate_target(url):
        return None

    try:
        return requests.get(
            url.strip(),
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException:
        return None


def load_openapi_spec(spec_url):
    if not validate_target(spec_url):
        return None

    try:
        response = requests.get(
            spec_url.strip(),
            timeout=TIMEOUT,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
        )
        response.raise_for_status()

        data = response.json()

        if (
            isinstance(data, dict)
            and ("openapi" in data or "swagger" in data)
            and isinstance(data.get("paths", {}), dict)
        ):
            return data

    except (requests.RequestException, ValueError):
        pass

    return None


def extract_endpoints(specification):
    endpoints = []

    if not isinstance(specification, dict):
        return endpoints

    paths = specification.get("paths", {})

    if not isinstance(paths, dict):
        return endpoints

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            if method.lower() not in SUPPORTED_METHODS:
                continue

            security = (
                operation.get(
                    "security",
                    specification.get("security"),
                )
                if isinstance(operation, dict)
                else specification.get("security")
            )

            entry = {
                "path": path,
                "method": method.upper(),
                "security_documented": bool(security),
            }

            if isinstance(operation, dict):
                if operation.get("summary"):
                    entry["summary"] = operation["summary"]

                if operation.get("operationId"):
                    entry["operation_id"] = operation["operationId"]

            endpoints.append(entry)

    return endpoints


def get_security_schemes(specification):
    if not isinstance(specification, dict):
        return {}

    components = specification.get("components", {})
    schemes = (
        components.get("securitySchemes", {})
        if isinstance(components, dict)
        else {}
    )

    if not schemes:
        schemes = specification.get("securityDefinitions", {})

    return schemes if isinstance(schemes, dict) else {}


# API1
def check_api1_bola():
    return result(
        "API1",
        "Broken Object Level Authorization",
        "review",
        "high",
        "Object-level authorization requires user-specific access tests.",
        "Test object access with authorized accounts.",
    )


# API2
def check_api2_authentication(specification=None):
    schemes = get_security_schemes(specification)
    endpoints = extract_endpoints(specification)

    secured = sum(
        1 for endpoint in endpoints
        if endpoint["security_documented"]
    )

    return result(
        "API2",
        "Broken Authentication",
        "review",
        "medium",
        f"Found {len(schemes)} documented security scheme(s) "
        f"and {secured} operation(s) with documented security. "
        "Runtime enforcement was not verified.",
        "Test authentication enforcement.",
        authentication_schemes=list(schemes.keys()),
        endpoint_count=len(endpoints),
        operations_with_security=secured,
    )


# API3
def check_api3_property_authorization(specification=None):
    if not isinstance(specification, dict):
        return result(
            "API3",
            "Broken Object Property Level Authorization",
            "not_tested",
            "info",
            "No OpenAPI specification was available.",
            "Inspect request and response models.",
        )

    components = specification.get("components", {})
    schemas = (
        components.get("schemas", {})
        if isinstance(components, dict)
        else {}
    )

    if not schemas:
        schemas = specification.get("definitions", {})

    if not isinstance(schemas, dict) or not schemas:
        return result(
            "API3",
            "Broken Object Property Level Authorization",
            "not_tested",
            "info",
            "No reusable schemas were found.",
            "Inspect request and response models.",
        )

    sensitive = []

    for name, schema in schemas.items():
        props = (
            schema.get("properties", {})
            if isinstance(schema, dict)
            else {}
        )

        if not isinstance(props, dict):
            continue

        for prop in props:
            normalized = prop.lower().replace("_", "").replace("-", "")

            if any(
                word in normalized
                for word in (
                    "password",
                    "secret",
                    "token",
                    "creditcard",
                    "ssn",
                )
            ):
                sensitive.append(f"{name}.{prop}")

    return result(
        "API3",
        "Broken Object Property Level Authorization",
        "review",
        "medium",
        f"Inspected {len(schemas)} schema(s); "
        f"found {len(sensitive)} potentially sensitive property name(s).",
        "Verify property-level authorization.",
        schema_count=len(schemas),
        potentially_sensitive_properties=sensitive[:50],
    )


# API4
def check_api4_resource_consumption(url):
    responses = []

    try:
        for index in range(5):
            response = requests.get(
                url.strip(),
                timeout=TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )

            responses.append({
                "request": index + 1,
                "status_code": response.status_code,
            })

            if response.status_code == 429:
                return result(
                    "API4",
                    "Unrestricted Resource Consumption",
                    "pass",
                    "info",
                    "HTTP 429 was observed during the low-volume check.",
                    "Review quotas and resource controls.",
                    evidence=responses,
                )

    except requests.RequestException:
        return result(
            "API4",
            "Unrestricted Resource Consumption",
            "not_tested",
            "medium",
            "The request check could not be completed.",
            "Verify target reachability.",
            evidence=responses,
        )

    return result(
        "API4",
        "Unrestricted Resource Consumption",
        "review",
        "medium",
        "Five sequential requests completed without HTTP 429.",
        "Review rate limits and other resource controls.",
        evidence=responses,
    )


# API5
def check_api5_function_authorization(specification=None):
    endpoints = extract_endpoints(specification)

    candidates = [
        endpoint
        for endpoint in endpoints
        if any(
            word in endpoint["path"].lower()
            for word in ("admin", "manage", "delete", "role", "permission")
        )
    ]

    return result(
        "API5",
        "Broken Function Level Authorization",
        "review",
        "high",
        f"Found {len(candidates)} potentially privileged operation(s).",
        "Test role permissions.",
        potentially_privileged_operations=candidates[:50],
    )


# API6
def check_api6_sensitive_business_flows(specification=None):
    paths = (
        specification.get("paths", {})
        if isinstance(specification, dict)
        else {}
    )

    keywords = (
        "login", "signin", "register", "password", "reset",
        "payment", "checkout", "transfer", "booking", "purchase",
    )

    found = [
        path
        for path in paths
        if any(word in path.lower() for word in keywords)
    ] if isinstance(paths, dict) else []

    return result(
        "API6",
        "Unrestricted Access to Sensitive Business Flows",
        "review",
        "medium",
        f"Found {len(found)} potentially sensitive business-flow path(s).",
        "Review business rules and abuse protection.",
        potentially_sensitive_paths=found[:50],
    )


# API7
def check_api7_ssrf(url, specification=None):
    return result(
        "API7",
        "Server-Side Request Forgery",
        "review",
        "high",
        "No SSRF payloads were sent during this scan.",
        "Review URL-fetching features and outbound request restrictions.",
    )


# API8
def check_api8_security_misconfiguration(url, response=None):
    findings = []

    if urlparse(url).scheme == "https":
        findings.append(result(
            "API8-HTTPS",
            "HTTPS",
            "pass",
            "info",
            "The supplied API URL uses HTTPS.",
            "Verify TLS configuration.",
        ))
    else:
        findings.append(result(
            "API8-HTTPS",
            "HTTPS",
            "fail",
            "medium",
            "The supplied API URL uses HTTP.",
            "Use HTTPS.",
        ))

    if response is None:
        findings.append(result(
            "API8-RESPONSE",
            "HTTP response",
            "not_tested",
            "info",
            "No response was available for inspection.",
            "Verify target reachability.",
        ))
        return findings

    for header in (
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
    ):
        present = header in response.headers

        findings.append(result(
            "API8-" + header,
            header,
            "pass" if present else "review",
            "info" if present else "low",
            f"{header} is {'present' if present else 'absent'} in the response.",
            f"Review the configuration of {header}.",
        ))

    return findings


# API9
def check_api9_inventory(specification=None):
    endpoints = extract_endpoints(specification)

    return result(
        "API9",
        "Improper Inventory Management",
        "review" if endpoints else "not_tested",
        "medium",
        f"Enumerated {len(endpoints)} documented operation(s).",
        "Compare documented endpoints against deployed routes.",
        endpoint_count=len(endpoints),
        endpoints=endpoints[:100],
    )


# API10
def check_api10_unsafe_consumption(specification=None):
    return result(
        "API10",
        "Unsafe Consumption of APIs",
        "review",
        "medium",
        "Third-party response validation was not verified.",
        "Validate external responses and trust boundaries.",
    )


# Five explicit presentation-only PASS entries
def create_demo_passes():
    names = [
        "Demo Check 1 - Scan Results Generated",
        "Demo Check 2 - OWASP Categories Listed",
        "Demo Check 3 - Findings Structure Available",
        "Demo Check 4 - Recommendations Field Available",
        "Demo Check 5 - Status Labels Available",
    ]

    findings = []

    for index, name in enumerate(names, start=1):
        findings.append({
            "id": f"DEMO-PASS-{index}",
            "check": name,
            "status": "pass",
            "severity": "info",
            "description": (
                "Presentation demonstration entry only. "
                "This does not confirm the target API is secure."
            ),
            "recommendation": (
                "Run and verify the corresponding real security test "
                "before treating it as a security result."
            ),
            "demo_only": True,
        })

    return findings


# Main scanner function
def scan_api(url: str, openapi_url: str = None) -> dict:
    if not validate_target(url):
        return {
            "status": "error",
            "message": "Invalid API target URL",
        }

    response = get_response(url)

    specification = (
        load_openapi_spec(openapi_url)
        if openapi_url
        else None
    )

    findings = [
        check_api1_bola(),
        check_api2_authentication(specification),
        check_api3_property_authorization(specification),
        check_api4_resource_consumption(url),
        check_api5_function_authorization(specification),
        check_api6_sensitive_business_flows(specification),
        check_api7_ssrf(url, specification),
    ]

    findings.extend(
        check_api8_security_misconfiguration(url, response)
    )

    findings.extend([
        check_api9_inventory(specification),
        check_api10_unsafe_consumption(specification),
    ])

    # Add five presentation-only PASS entries for every valid target URL.
    findings.extend(create_demo_passes())

    return {
        "status": "completed",
        "target": url,
        "openapi_url": openapi_url,
        "openapi_status": (
            "loaded" if specification is not None
            else "not_provided" if not openapi_url
            else "unavailable_or_invalid"
        ),
        "owasp_version": "OWASP API Security Top 10 - 2023",
        "findings": findings,
    }