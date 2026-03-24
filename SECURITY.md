# Security Policy

This document describes how to report security issues in **BreathGSLB**, an authoritative DNS and GSLB engine developed by AKADATA.

The goal is to protect operators, infrastructure, and data while keeping the project open, reliable, and practical for real-world deployment.

---

## Supported Versions and Branches

Security reports are welcome for:

* The `master` branch of this repository on GitHub.
* Official releases (e.g., tagged versions such as `v0.0.1`).
* Actively maintained branches referenced in the README.

Experimental branches, local forks, and modified deployments outside this repository fall outside this policy.

---

## What Counts as a Security Issue

Examples of issues treated as security-relevant include:

* Authoritative DNS behaviour that could lead to incorrect, unsafe, or unintended responses affecting routing or service availability.
* DNSSEC implementation flaws (NSEC/NSEC3, key handling, signing) that could:

  * Break validation
  * Leak information
  * Allow spoofed or invalid responses
* Issues in health-check logic that could be abused to:

  * Force incorrect failover
  * Cause persistent denial of service
* Remote or local code execution via configuration, API endpoints, or network input.
* Privilege escalation when running BreathGSLB on a host system.
* AXFR/IXFR or replication issues that expose zone data to unauthorized parties.
* TSIG or key-handling weaknesses that allow unauthorized transfers or control.
* API-related vulnerabilities (current or future), including authentication, authorization, and data exposure.
* Malicious behaviour or compromise in distributed binaries or release artifacts.

Bugs that result only in crashes, misconfiguration, or incorrect output without a realistic security impact are treated as standard defects.

---

## How to Report a Vulnerability

Private disclosure is preferred so issues can be understood and fixed before public discussion.

Use one of the following:

* Email: **[security@akadata.ltd](mailto:security@akadata.ltd)**
* GitHub: open a **Private security advisory** in the repository Security tab

Please include where possible:

* Clear description of the issue and its impact
* Version or commit hash
* Deployment details (OS, architecture, environment)
* Configuration snippets (sanitised where needed)
* Steps to reproduce
* Proof-of-concept or test data (if available)

Logs and query traces (e.g., `dig` output) are particularly helpful.

---

## What to Expect

After receiving a report:

1. **Acknowledgement** – Confirmation that the report has been received
2. **Triage** – Classification as a security issue or standard defect
3. **Validation** – Reproduction and impact analysis
4. **Fix or Mitigation** – Development of a patch or workaround
5. **Disclosure** – Coordinated release of the fix where appropriate

Security issues take priority over feature development.

---

## Responsible Disclosure

When a vulnerability is identified, please avoid publishing full exploit details until a fix or mitigation is available.

Discussion of general DNS, GSLB, or infrastructure security concepts is welcome publicly. Specific vulnerabilities are best handled privately first.

---

## Out of Scope

The following are out of scope:

* Vulnerabilities in third-party DNS resolvers or client software
* Issues in operating systems, kernels, or network stacks not triggered specifically by BreathGSLB
* Misconfiguration by operators (unless it reveals unsafe defaults)
* Physical access attacks against infrastructure
* Behaviour in modified forks not maintained by AKADATA

---

## Cryptography and Key Handling

BreathGSLB includes DNSSEC functionality with automated handling of key material.

When reporting issues in this area:

* Treat keys and payloads as sensitive
* Do not publish private keys or secrets
* Share minimal reproducible data only

The aim is to improve safety without exposing real-world deployments.

---

## Commitment

BreathGSLB is designed to be:

* Authoritative and predictable
* Transparent in behaviour
* Secure by design where possible

When issues are found, they will be addressed directly and without delay.

---

## Thanks

Every report that improves the safety and reliability of BreathGSLB is appreciated.

Strong DNS foundations keep services reachable, stable, and trustworthy.
