# CERBERUS — Cybersecurity Assessment & Response Platform

CERBERUS is a cybersecurity assessment and response platform designed to bring Web Application Security, API Security, and Security Operations together in a unified dashboard.

## Project Overview

The platform provides security assessment capabilities for web applications and APIs, along with a separate workflow for security event management and incident response.

## Key Modules

### 1. Web Application Security
- Performs security checks based on the OWASP Top 10.
- Identifies potential web application security issues.
- Displays scan findings and assessment results.

### 2. API Security
- Performs API security assessments based on the OWASP API Security Top 10.
- Supports API URL and optional OpenAPI specification input.
- Displays security findings and assessment results.

### 3. Security Operations
- Supports security event creation and management.
- Provides event investigation workflows.
- Supports incident response record management.
- Follows the Detect → Investigate → Respond workflow.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, Vite, CSS |
| Backend | Python, FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Authentication | JWT |
| Password Hashing | Argon2id |

## Main Features

- Unified cybersecurity dashboard.
- Web application security assessment.
- API security assessment.
- Security event management.
- Incident investigation and response workflows.
- User authentication.
- Centralized assessment results.

## Project Structure

```text
CERBERUS/
├── backend/
│   ├── api_security/
│   ├── auth/
│   ├── models/
│   ├── security_operations/
│   ├── web_security/
│   └── main.py
│
├── frontend/
│   ├── public/
│   ├── src/
│   └── package.json
│
└── .gitignore
```

## Project Objectives

- Understand common web application vulnerabilities.
- Assess API security risks.
- Develop practical cybersecurity assessment capabilities.
- Understand security event investigation and incident response workflows.
- Integrate frontend, backend, and database technologies.

## Limitations

- Security scanning coverage is limited to implemented checks.
- Some findings may require manual verification.
- CERBERUS is an academic prototype, not a complete penetration-testing platform.
- Security Operations is a separate workflow; scan findings do not automatically become incidents.

## Disclaimer

CERBERUS is developed for educational and authorized security assessment purposes. Only test systems for which you have permission.

## Project Status

Academic cybersecurity project — developed as a learning and practical implementation project.

---

**Developed by:** Kavaskar Murugesh
