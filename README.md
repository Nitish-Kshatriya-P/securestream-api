# SecureStream API Gateway

A production-grade secure REST API simulating a medical 
Video-on-Demand (VOD) platform, built to demonstrate 
security engineering practices across authentication, 
cryptography, traffic analysis, and real-time threat detection.

## Live Demo
API Health Check: https://65.1.131.90/health

---

## Project Summary

**Security Architecture:**
Designed and deployed a production-grade REST API simulating 
a medical Video-on-Demand platform with six independent 
defensive layers. Implemented JWT authentication with bcrypt 
password hashing, AES-256 Fernet URL tokenization with 
5-minute expiry to prevent content hotlinking, and HMAC-SHA256 
request signing to block parameter tampering. Built a documented 
threat model identifying credential stuffers, content scrapers, 
replay attackers, and MITM adversaries before writing a single 
line of application code.

**Real-Time Threat Detection:**
Architected a complete SIEM pipeline — structured JSON audit 
logs written by FastAPI, shipped via Filebeat to Elasticsearch, 
and visualised in Kibana with custom alert rules. Credential 
stuffing detection fires when three or more AUTH_FAILURE events 
originate from the same source within five minutes. Parameter 
tampering detection fires on any HMAC_FAILURE event. Both rules 
demonstrated live with simulated attacks during development and 
verified via Kibana alert dashboard screenshots.

**Supply Chain Security & Cloud Deployment:**
Identified and remediated four CVEs during development including 
CVE-2024-23342 (ecdsa timing side-channel), two 2026 pip 
vulnerabilities, and a pyasn1 deserialisation flaw — all caught 
via pip-audit and fixed with documented commit messages. Deployed 
to AWS EC2 t3.micro with hardened Security Groups restricting SSH 
to a single IP, least-privilege IAM role, and TLS enforced on all 
endpoints.

---

## Security Architecture

| Layer | Technology | Threat Mitigated |
|---|---|---|
| Authentication | JWT + bcrypt | Credential theft |
| URL Protection | AES-256 Tokenization | Content hotlinking |
| Request Integrity | HMAC-SHA256 | Parameter tampering |
| Transport Security | TLS 1.3 | MITM interception |
| Rate Limiting | slowapi | Credential stuffing |
| Threat Detection | Elastic SIEM | Real-time attack alerting |
| Dependency Security | pip-audit | Supply chain attacks |

---

## API Endpoints

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| GET | /health | None | Public health check |
| POST | /auth/login | None | Returns signed JWT |
| GET | /stream/{content_id} | JWT + HMAC | Returns AES media token |
| GET | /stream/resolve/{token} | None | Resolves token to media URL |

---

## Key Security Features

### AES-256 Media Tokenization
Media URLs are never exposed directly. Each request generates 
an encrypted, time-limited token (5 minute TTL) that resolves 
to the actual content URL server-side. Tokens are stateless 
and self-validating — no database lookup required.

### HMAC-SHA256 Request Signing
Every stream request must include a valid HMAC-SHA256 signature 
over the request parameters. The server recomputes the signature 
independently — any parameter modification produces a mismatch 
and the request is rejected with 401.

### Real-Time SIEM Alerting
Structured JSON audit logs ship via Filebeat to Elasticsearch. 
Kibana alert rules fire on credential stuffing attempts 
(3+ AUTH_FAILURE in 5 minutes) and parameter tampering 
(any HMAC_FAILURE event).

### Supply Chain Security
pip-audit runs at every install. Four CVEs identified and 
remediated during development — including CVE-2024-23342 
(ecdsa timing side-channel attack).

---

## Threat Model
See [THREAT_MODEL.md](THREAT_MODEL.md) for full asset 
inventory, threat actor profiles, attack vectors, security 
controls, and residual risks.

---

## Tech Stack

| Category | Technology |
|---|---|
| Framework | Python 3.11, FastAPI |
| Authentication | PyJWT, passlib (bcrypt) |
| Cryptography | cryptography (Fernet AES-256), hmac, hashlib |
| Rate Limiting | slowapi |
| SIEM | Elasticsearch, Kibana, Filebeat |
| Cloud | AWS EC2 t3.micro, AWS IAM |
| Transport Security | OpenSSL, TLS |
| Dependency Audit | pip-audit |
