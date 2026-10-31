import yaml
import os

class PolicyRecommender:
    def __init__(self, config_path='config.yaml'):
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {}

    def get_recommendations(self):
        return [
            {
                "category": "Cryptographic Hash Migration",
                "status": "CRITICAL",
                "finding": "Usage of legacy fast hashes (MD5, SHA-1, raw SHA-256)",
                "recommendation": "Immediately transition to Argon2id (RFC 9106) or bcrypt (cost >= 12). Raw cryptographic digests allow attackers to compute billions of guesses per second on consumer hardware.",
                "standard": "NIST SP 800-63B §5.1.1.2 / OWASP Password Storage Cheat Sheet"
            },
            {
                "category": "Password Length & Composition",
                "status": "HIGH",
                "finding": "Short passwords (< 12 characters) or rigid composition requirements",
                "recommendation": "Enforce minimum length of 12-16 characters. Retire legacy composition rules (e.g. mandatory uppercase/symbol) in favor of length, as length yields exponentially greater entropy.",
                "standard": "NIST SP 800-63B §5.1.1.1"
            },
            {
                "category": "Compromised Credential Screening",
                "status": "HIGH",
                "finding": "Absence of real-time breach detection during onboarding / updates",
                "recommendation": "Screen new passwords against known public breach dumps using k-Anonymity (HIBP API) during account creation and password changes.",
                "standard": "NIST SP 800-63B §5.1.1.2"
            },
            {
                "category": "Password Expiration & Rotation",
                "status": "MEDIUM",
                "finding": "Arbitrary 60-90 day forced password rotation policies",
                "recommendation": "Discontinue arbitrary scheduled password rotations. Empirical security studies show forced rotation leads to predictable variations (e.g., Summer2024! -> Fall2024!). Rotate only upon evidence of compromise.",
                "standard": "NIST SP 800-63B §5.1.1.2"
            },
            {
                "category": "Multi-Factor Authentication (MFA)",
                "status": "MUST-HAVE",
                "finding": "Single-factor password-only access boundaries",
                "recommendation": "Mandate FIDO2/WebAuthn passkeys or RFC 6238 TOTP authenticators for all administrative and authenticated user endpoints.",
                "standard": "CISA Cross-Sector Cybersecurity Performance Goals"
            },
            {
                "category": "Rate Limiting & Credential Stuffing Defense",
                "status": "BEST PRACTICE",
                "finding": "Unthrottled authentication endpoints",
                "recommendation": "Deploy IP-reputation filtering, adaptive CAPTCHA, and account-level velocity tracking to mitigate distributed stuffing attacks.",
                "standard": "OWASP Automated Threat Handbook (OAT-008)"
            }
        ]

    def evaluate_organization_policy(self, min_length=12, allow_passphrases=True, force_rotation_days=0, enforce_breach_check=True, enforce_mfa=True, hash_algorithm="argon2id"):
        """
        Audit a corporate password policy against modern NIST SP 800-63B and OWASP guidelines.
        Returns a compliance score (0-100) and line-item analysis.
        """
        score = 100
        findings = []

        # Check Algorithm
        algo_lower = hash_algorithm.lower()
        if "argon2" in algo_lower:
            findings.append({"item": "Storage Hash Algorithm", "status": "EXCELLENT", "detail": "Argon2id deployed. State-of-the-art memory-hard resistance.", "penalty": 0})
        elif "bcrypt" in algo_lower:
            findings.append({"item": "Storage Hash Algorithm", "status": "GOOD", "detail": "bcrypt deployed. Proven enterprise standard with adaptive work factor.", "penalty": 0})
        elif "sha256" in algo_lower or "sha512" in algo_lower:
            score -= 35
            findings.append({"item": "Storage Hash Algorithm", "status": "CRITICAL RISK", "detail": "Raw SHA-256/SHA-512 is not an adaptive password hash. Easily cracked on GPUs.", "penalty": 35})
        else: # MD5 / SHA-1
            score -= 50
            findings.append({"item": "Storage Hash Algorithm", "status": "FATAL RISK", "detail": "MD5/SHA-1 is fundamentally broken and obsolete.", "penalty": 50})

        # Check Length
        if min_length >= 14:
            findings.append({"item": "Minimum Length Requirement", "status": "EXCELLENT", "detail": f"{min_length} characters enforces high baseline entropy.", "penalty": 0})
        elif min_length >= 10:
            findings.append({"item": "Minimum Length Requirement", "status": "ACCEPTABLE", "detail": f"{min_length} characters meets standard baseline.", "penalty": 0})
        elif min_length >= 8:
            score -= 10
            findings.append({"item": "Minimum Length Requirement", "status": "MARGINAL", "detail": "8 characters is NIST absolute minimum; consider raising to 12+.", "penalty": 10})
        else:
            score -= 25
            findings.append({"item": "Minimum Length Requirement", "status": "NON-COMPLIANT", "detail": f"{min_length} characters is below NIST minimum (8).", "penalty": 25})

        # Check Rotation
        if force_rotation_days == 0:
            findings.append({"item": "Password Expiration Policy", "status": "NIST ALIGNED", "detail": "No arbitrary expiration. Passwords rotated only on compromise.", "penalty": 0})
        elif force_rotation_days <= 90:
            score -= 15
            findings.append({"item": "Password Expiration Policy", "status": "OUTDATED PRACTICE", "detail": f"Forced {force_rotation_days}-day rotation violates NIST SP 800-63B guidance; leads to weaker passwords.", "penalty": 15})
        else:
            findings.append({"item": "Password Expiration Policy", "status": "LENIENT", "detail": f"{force_rotation_days}-day rotation configured.", "penalty": 0})

        # Check Breach Lookup
        if enforce_breach_check:
            findings.append({"item": "Breach Corpus Screening", "status": "COMPLIANT", "detail": "K-Anonymity breach screening actively prevents compromised passwords.", "penalty": 0})
        else:
            score -= 20
            findings.append({"item": "Breach Corpus Screening", "status": "DEFICIENCY", "detail": "Lack of breach screening permits previously leaked passwords to be used.", "penalty": 20})

        # Check MFA
        if enforce_mfa:
            findings.append({"item": "Multi-Factor Authentication", "status": "ENFORCED", "detail": "MFA acts as vital secondary barrier against credential theft.", "penalty": 0})
        else:
            score -= 30
            findings.append({"item": "Multi-Factor Authentication", "status": "VULNERABLE", "detail": "Single factor passwords remain single point of failure.", "penalty": 30})

        score = max(0, min(100, score))
        if score >= 90: grade = "A+ (Enterprise Resilient)"
        elif score >= 80: grade = "A (NIST Aligned)"
        elif score >= 70: grade = "B (Acceptable Defense)"
        elif score >= 50: grade = "C (Significant Exposure)"
        else: grade = "F (High Vulnerability)"

        return {
            'score': score,
            'grade': grade,
            'findings': findings
        }

    def get_defense_methodologies(self):
        """Returns deep-dive defensive methodologies."""
        return [
            {
                "title": "🛡️ The Cryptographic Salt Barrier",
                "tag": "ANTI-RAINBOW TABLE",
                "description": "Never store passwords in plain text or with static global salts. Unique per-user salts ensure identical passwords hash to completely divergent ciphertext.",
                "steps": [
                    "Generate 16-byte cryptographically secure random salt (CSPRNG)",
                    "Combine with plaintext before key derivation function",
                    "Store salt alongside hash digest in auth database",
                    "Argon2 and bcrypt automate per-record salting by design"
                ]
            },
            {
                "title": "🧠 Adaptive Work Factors & Memory Hardness",
                "tag": "HARDWARE RESISTANCE",
                "description": "Standard hashes execute in microseconds, granting attackers billion-guesses-per-second GPU clusters. Memory-hard algorithms neutralize ASIC/GPU advantages.",
                "steps": [
                    "Select Argon2id with 64 MB memory cost and 2-3 iterations",
                    "Calibrate server verification latency to 100-250 milliseconds",
                    "Defeat GPU parallelization by requiring large memory per thread",
                    "Incrementally adjust work factors as hardware speeds increase"
                ]
            },
            {
                "title": "🧱 Rate Limiting & Account Velocity Controls",
                "tag": "ONLINE BRUTE FORCE",
                "description": "Stop online credential attacks before computation begins. Throttling renders online password guessing statistically impossible.",
                "steps": [
                    "Implement progressive delay (exponential backoff) after failed attempts",
                    "Deploy IP and ASN-based anomaly scoring",
                    "Trigger CAPTCHA challenges after 3 consecutive failures",
                    "Enforce intelligent account lockouts with out-of-band unlock"
                ]
            },
            {
                "title": "🔐 Zero-Knowledge Breach Screening (K-Anonymity)",
                "tag": "PRIVACY-PRESERVING",
                "description": "Verify passwords against 10+ billion public breach records without exposing user credentials to third-party endpoints.",
                "steps": [
                    "Compute SHA-1 hash of user's candidate password locally",
                    "Send only the first 5 characters (prefix) to HIBP API",
                    "Receive 500-800 matching hash suffixes over encrypted HTTPS",
                    "Perform exact suffix match locally in client memory"
                ]
            },
            {
                "title": "🗝️ Defense-in-Depth: Secret Peppering & HSM Storage",
                "tag": "DATABASE EXFILTRATION DEFENSE",
                "description": "Apply a secondary server-side secret key (pepper) or Hardware Security Module (HSM) HMAC.",
                "steps": [
                    "Maintain an encrypted application-level secret (pepper) separate from database",
                    "Combine pepper with salted password prior to hashing or wrap in HMAC",
                    "In the event of a SQL database dump, attackers cannot crack hashes without the pepper"
                ]
            }
        ]

    def get_benchmark_comparison(self):
        return [
            {"Algorithm": "MD5", "Security Status": "BROKEN", "Salt Built-in": "No", "Memory Hardness": "None", "8x RTX 4090 Speed": "360+ GH/s", "Recommended Action": "Eliminate immediately"},
            {"Algorithm": "SHA-1", "Security Status": "DEPRECATED", "Salt Built-in": "No", "Memory Hardness": "None", "8x RTX 4090 Speed": "120+ GH/s", "Recommended Action": "Replace with Argon2id"},
            {"Algorithm": "SHA-256", "Security Status": "FAST CRYPTO", "Salt Built-in": "No", "Memory Hardness": "None", "8x RTX 4090 Speed": "80+ GH/s", "Recommended Action": "Unsafe for passwords alone"},
            {"Algorithm": "bcrypt", "Security Status": "ENTERPRISE", "Salt Built-in": "Yes (128-bit)", "Memory Hardness": "4 KB (CPU-bound)", "8x RTX 4090 Speed": "1.2 MH/s", "Recommended Action": "Cost factor >= 12"},
            {"Algorithm": "scrypt", "Security Status": "STRONG", "Salt Built-in": "Yes", "Memory Hardness": "Configurable (MBs)", "8x RTX 4090 Speed": "< 200 kH/s", "Recommended Action": "Solid ASIC resistance"},
            {"Algorithm": "Argon2id", "Security Status": "GOLD STANDARD", "Salt Built-in": "Yes (128-bit)", "Memory Hardness": "Configurable (64 MB+)", "8x RTX 4090 Speed": "< 16 kH/s", "Recommended Action": "Primary standard (RFC 9106)"},
        ]
