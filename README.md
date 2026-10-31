# 🛡️ HashSentinel Enterprise: Cryptographic Password Hash & Security Assessment Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Standard: NIST SP 800-63B](https://img.shields.io/badge/Standard-NIST%20SP%20800--63B-emerald.svg)](https://pages.nist.gov/800-63-3/sp800-63b.html)
[![RFC: 9106 Argon2](https://img.shields.io/badge/RFC-9106%20Argon2id-indigo.svg)](https://datatracker.ietf.org/doc/html/rfc9106)

An enterprise-grade cybersecurity platform for analyzing password entropy, benchmarking modern and legacy cryptographic hashing algorithms, evaluating corporate password policy compliance, and simulating adversary cracking attacks. Built for security engineers, cryptographers, and system architects to understand and strengthen modern authentication systems.

---

## 🏗️ Platform Architecture & Workspaces

The platform is partitioned into 6 specialized security modules:

1. **📊 Executive Overview & Security Posture**
   - High-level KPIs: Hash Hardness Index, NIST Alignment, HIBP Breach Corpus Coverage, and Legacy Hash Exposure.
   - Algorithm Maturity & Hardware Resistance Chart (comparison against 8x NVIDIA RTX 4090 cluster).
   - Real-time zero-lag quick password screening widget.

2. **🧬 Real-Time Entropy & Breach Intelligence**
   - Heuristic entropy calculation: Pool Entropy ($N^L$) and Shannon Symbol Diversity.
   - Privacy-preserving HaveIBeenPwned API integration via SHA-1 **k-Anonymity model**.
   - Adversary Hardware Crack Time Projections across 4 tiers (Laptop CPU, Single RTX 4090, 8x GPU Cluster, Cloud Botnet).
   - NIST-recommended memorable multi-word passphrases and high-entropy cryptographic token generators.

3. **⚡ Cryptographic Hash Engine & Benchmarking**
   - Multi-algorithm hashing: MD5, SHA-1, SHA-256, SHA-512, bcrypt, scrypt, and Argon2id.
   - Real-time host hardware benchmark with customizable bcrypt work-factors and Argon2 time/memory costs.
   - **Hash Deconstruction & Forensic Inspector**: Paste any hash to detect algorithm, salt presence, work factor, and risk level.

4. **🎯 Adversary Attack & Cracking Lab**
   - **The Salt Defense Proof**: Side-by-side demonstration of unsalted MD5 (identical hashes, vulnerable to Rainbow Tables) vs salted bcrypt/Argon2 (unique hashes, defeating Rainbow Tables).
   - Live dictionary attack simulator with common breached credential rules.
   - Brute-Force Feasibility, Power & Economic Cost Calculator (calculates keyspace, crack duration, and electricity cost in USD).

5. **🛡️ Enterprise Policy & NIST Framework**
   - Interactive Corporate Password Policy Auditor: Score corporate rules (length, expiration, MFA, breach screening) with an objective A+ to F grade.
   - NIST SP 800-63B & OWASP digital identity alignment guide.
   - Defensive engineering blueprints: Salted perimeters, adaptive work factors, rate limiting, and HSM peppering.

6. **📑 Executive Security Audit Report**
   - Generates executive-ready, professional PDF audit documents with executive summaries, technical benchmarks, and prioritized strategic recommendations.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- All dependencies from `requirements.txt`

### Launch the Platform
```powershell
$env:PYTHONIOENCODING="utf-8"
& "C:\Users\Omar Abu Saeed\AppData\Local\Programs\Python\Python311\python.exe" -m streamlit run dashboard/app.py
```
Open **`http://localhost:8501`** in your browser.

---

## 🧪 Running Unit Tests
```powershell
& "C:\Users\Omar Abu Saeed\AppData\Local\Programs\Python\Python311\python.exe" -m pytest
```

---

## ⚖️ Ethical & Legal Notice
This project is engineered strictly for **authorized educational, administrative, and professional defensive cybersecurity assessments**. Unauthorized testing against systems without prior written consent violates relevant state and federal cybercrime statutes.
