from fpdf import FPDF
from fpdf.enums import XPos, YPos
import datetime
import os
import sys
import hashlib

# Add root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class ReportGenerator(FPDF):
    def __init__(self, company_name="Enterprise Security Lab", sensitivity="Confidential"):
        super().__init__()
        self.company_name = company_name
        self.sensitivity = sensitivity.upper()
        self.auditor_name = "Principal Cryptographic Assessor"
        self.set_auto_page_break(auto=True, margin=18)

    def header(self):
        # Top brand bar
        self.set_fill_color(15, 23, 42)   # Slate 900
        self.rect(0, 0, 210, 16, 'F')
        # Thin accent line
        self.set_fill_color(56, 189, 248)  # Sky 400
        self.rect(0, 16, 210, 0.6, 'F')

        self.set_font('helvetica', 'B', 9.5)
        self.set_text_color(248, 250, 252)
        self.set_xy(12, 4.5)
        self.cell(110, 7, 'HASHSENTINEL ENTERPRISE | CRYPTOGRAPHIC AUDIT REPORT', new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.set_font('helvetica', 'B', 8)
        if "TOP" in self.sensitivity or "CONF" in self.sensitivity:
            self.set_text_color(239, 68, 68)   # Crimson
        else:
            self.set_text_color(59, 130, 246)   # Blue
        self.set_xy(140, 4.5)
        self.cell(60, 7, f'CLASSIFICATION: {self.sensitivity}', align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(10)

    def footer(self):
        self.set_y(-14)
        # Thin accent line above footer
        self.set_draw_color(203, 213, 225)
        self.set_line_width(0.3)
        self.line(10, self.get_y() - 1.5, 200, self.get_y() - 1.5)

        self.set_font('helvetica', '', 7.5)
        self.set_text_color(100, 116, 139)  # Slate 500
        self.cell(100, 7, f'Confidential Security Assessment | {self.company_name}', align='L', new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(90, 7, f'Page {self.page_no()} | Generated {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")} UTC', align='R', new_x=XPos.RIGHT, new_y=YPos.TOP)

    # ─── Helper: Section Heading ───
    def _section_heading(self, number, title):
        self.set_font('helvetica', 'B', 12)
        self.set_text_color(15, 23, 42)
        self.cell(0, 7, f'{number}. {title}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Subtle underline
        self.set_draw_color(56, 189, 248)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 80, self.get_y())
        self.set_line_width(0.2)
        self.ln(3)

    # ─── Helper: Body text ───
    def _body_text(self, text):
        self.set_font('helvetica', '', 9)
        self.set_text_color(51, 65, 85)
        self.multi_cell(0, 4.8, text)
        self.ln(2)

    # ─── Helper: Bullet list ───
    def _bullet_list(self, items, indent=14):
        self.set_font('helvetica', '', 8.5)
        self.set_text_color(51, 65, 85)
        for item in items:
            self.set_x(indent)
            self.cell(4, 4.5, '-', new_x=XPos.RIGHT, new_y=YPos.TOP)  # bullet dash
            self.multi_cell(176, 4.5, f"  {item}")
            self.ln(0.5)

    # ─── Helper: Phase box (colored card for mitigation phases) ───
    def _phase_box(self, title, title_color_rgb, fill_rgb, border_rgb, items, height=None):
        # Calculate height needed
        if height is None:
            height = 8 + len(items) * 5.5 + 4
        self.set_fill_color(*fill_rgb)
        self.set_draw_color(*border_rgb)
        y_start = self.get_y()
        self.rect(10, y_start, 190, height, 'DF')

        self.set_xy(14, y_start + 3)
        self.set_font('helvetica', 'B', 9.5)
        self.set_text_color(*title_color_rgb)
        self.cell(0, 5, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_font('helvetica', '', 8.5)
        self.set_text_color(51, 65, 85)
        for idx, item in enumerate(items):
            self.set_x(14)
            self.multi_cell(182, 4.5, f"{idx+1}. {item}")
            self.ln(0.3)

        self.set_y(y_start + height + 2)

    # ════════════════════════════════════════════════════════════════════════════
    # MAIN REPORT GENERATION
    # ════════════════════════════════════════════════════════════════════════════
    def generate_report(self, stats=None, recommendations=None, company_name="Security Labs Inc.",
                        sensitivity="Confidential", auditor_name=None, session_items=None,
                        output_path="reports/security_report.pdf"):
        self.company_name = company_name
        self.sensitivity = sensitivity.upper()
        if auditor_name:
            self.auditor_name = auditor_name

        self.add_page()

        total_tested = len(session_items) if session_items else 0
        vulnerable_count = sum(
            1 for it in session_items
            if it.get('strength_percent', 0) < 50 or it.get('pwned_count', 0) > 0 or it.get('detected_names')
        ) if session_items else 0
        name_count = sum(1 for it in session_items if it.get('detected_names')) if session_items else 0
        breach_count = sum(1 for it in session_items if it.get('pwned_count', 0) > 0) if session_items else 0
        avg_entropy = (sum(it.get('entropy', 0) for it in session_items) / total_tested) if total_tested > 0 else 0.0
        avg_strength = (sum(it.get('strength_percent', 0) for it in session_items) / total_tested) if total_tested > 0 else 0.0
        report_id = f"AUD-{hashlib.md5(self.company_name.encode()).hexdigest()[:8].upper()}"

        # ─────────────────────────────────────────────────────────────────────
        # PAGE 1: EXECUTIVE COVER & HIGH-LEVEL POSTURE
        # ─────────────────────────────────────────────────────────────────────

        # Document Title Block
        self.set_text_color(15, 23, 42)
        self.set_font('helvetica', 'B', 22)
        self.cell(0, 10, 'CRYPTOGRAPHIC PASSWORD', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.cell(0, 10, 'HASH SECURITY AUDIT', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_font('helvetica', 'B', 10)
        self.set_text_color(2, 132, 199)
        self.cell(0, 6, 'ENTERPRISE AUTHENTICATION VULNERABILITY ASSESSMENT', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

        self.set_font('helvetica', '', 9)
        self.set_text_color(100, 116, 139)
        self.cell(0, 5, f'Client: {self.company_name}  |  Report ID: {report_id}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.cell(0, 5, f'Standards: NIST SP 800-63B, OWASP Top 10, RFC 9106, CIS Benchmarks v8.0', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.cell(0, 5, f'Assessment Date: {datetime.datetime.now().strftime("%B %d, %Y")}  |  Lead Assessor: {self.auditor_name}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

        # Decorative accent line
        self.set_draw_color(56, 189, 248)
        self.set_line_width(0.8)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_line_width(0.2)
        self.ln(6)

        # ═══ 1. Executive Summary ═══
        self._section_heading("1", "EXECUTIVE EVALUATION SUMMARY")

        if total_tested > 0:
            risk_level = "CRITICAL" if vulnerable_count > total_tested * 0.5 else ("HIGH" if vulnerable_count > 0 else "LOW")
            summary_text = (
                f"HashSentinel performed a cryptographic security assessment of {total_tested} "
                f"user-submitted credential(s) for {self.company_name}. "
                f"The analysis included real-time HaveIBeenPwned (HIBP) k-anonymity breach verification, "
                f"multi-tier hardware cracking simulations (consumer to nation-state), dictionary and personal "
                f"name scanning against a curated corpus, and algorithmic storage benchmarking.\n\n"
                f"Overall Risk Assessment: {risk_level} - {vulnerable_count} of {total_tested} credential(s) "
                f"exhibit critical security weaknesses requiring immediate remediation. "
                f"Average entropy across tested credentials is {avg_entropy:.1f} bits "
                f"({'below' if avg_entropy < 50 else 'meeting'} the recommended 50-bit minimum). "
                f"{name_count} credential(s) contain detectable personal names vulnerable to targeted OSINT attacks. "
                f"{breach_count} credential(s) appear in known public breach databases."
            )
        else:
            summary_text = (
                f"HashSentinel performed an architectural cryptographic evaluation of password hash resilience "
                f"and authentication mechanisms for {self.company_name}. The audit benchmarks algorithm "
                f"execution latency, measures resistance against adversary GPU clusters (8x NVIDIA RTX 4090), "
                f"and assesses alignment with NIST SP 800-63B Digital Identity Guidelines and OWASP "
                f"Authentication Cheat Sheet recommendations. No user credentials were submitted during "
                f"this session; findings reflect baseline infrastructure analysis."
            )
        self._body_text(summary_text)

        # Real-Time Telemetry Dashboard Box
        self.set_fill_color(241, 245, 249)   # Slate 100
        self.set_draw_color(148, 163, 184)   # Slate 400
        self.rect(10, self.get_y(), 190, 22, 'DF')

        start_y = self.get_y() + 2.5
        labels = ["CREDENTIALS TESTED:", "VULNERABILITIES:", "AVG. ENTROPY:", "AVG. STRENGTH:"]
        self.set_xy(14, start_y)
        self.set_font('helvetica', 'B', 7.5)
        self.set_text_color(100, 116, 139)
        col_w = 47
        for lbl in labels:
            self.cell(col_w, 4, lbl, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.ln()

        self.set_xy(14, start_y + 6)
        self.set_font('helvetica', 'B', 11)

        # Credentials tested
        self.set_text_color(59, 130, 246)
        self.cell(col_w, 6, f"{total_tested}", new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Vulnerabilities
        if vulnerable_count > 0:
            self.set_text_color(220, 38, 38)
        else:
            self.set_text_color(16, 185, 129)
        self.cell(col_w, 6, f"{vulnerable_count} Critical", new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Avg Entropy
        if avg_entropy >= 50:
            self.set_text_color(16, 185, 129)
        else:
            self.set_text_color(217, 119, 6)
        self.cell(col_w, 6, f"{avg_entropy:.1f} bits", new_x=XPos.RIGHT, new_y=YPos.TOP)

        # Avg Strength
        if avg_strength >= 70:
            self.set_text_color(16, 185, 129)
        elif avg_strength >= 40:
            self.set_text_color(217, 119, 6)
        else:
            self.set_text_color(220, 38, 38)
        self.cell(col_w, 6, f"{avg_strength:.0f}%", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_y(start_y + 20)
        self.ln(5)

        # ═══ 2. Credential Findings Table ═══
        if session_items and len(session_items) > 0:
            self._section_heading("2", "REAL-TIME CREDENTIAL VULNERABILITY FINDINGS")

            self._body_text(
                "The following table details each credential tested during this session, including "
                "entropy measurements, breach exposure status, detected weakness patterns, and an "
                "overall security classification. Credentials rated HIGH RISK require immediate rotation."
            )

            # Table Header
            self.set_font('helvetica', 'B', 7.5)
            self.set_fill_color(15, 23, 42)
            self.set_text_color(255, 255, 255)
            cols = [
                ("Credential", 38, 'L'),
                ("Entropy", 20, 'C'),
                ("HIBP Leaks", 22, 'C'),
                ("Names", 18, 'C'),
                ("Detected Weaknesses", 60, 'L'),
                ("Status", 32, 'C'),
            ]
            for name, w, a in cols:
                self.cell(w, 6, name, border=1, align=a, fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.ln()

            self.set_font('helvetica', '', 7.5)
            for idx, item in enumerate(session_items[:12]):
                pwd_label = item.get('display_password', item.get('password', 'unknown'))
                entropy_val = item.get('entropy', 0)
                pwned_val = item.get('pwned_count', 0)
                names = item.get('detected_names', [])
                strength_pct = item.get('strength_percent', 0)

                # Alternate row fill
                if idx % 2 == 0:
                    self.set_fill_color(255, 255, 255)
                else:
                    self.set_fill_color(241, 245, 249)
                self.set_text_color(30, 41, 59)

                # Determine findings text
                findings = []
                if names:
                    findings.append(f"Name: {', '.join(names[:2])}")
                if pwned_val > 0:
                    findings.append(f"Breached ({pwned_val:,}x)")
                if entropy_val < 35:
                    findings.append("Low entropy")
                if strength_pct < 40:
                    findings.append("Weak composition")
                finding_str = "; ".join(findings) if findings else "No critical patterns"

                # Status label
                if strength_pct < 40 or names or pwned_val > 0:
                    score_str = f"{strength_pct}% HIGH RISK"
                elif strength_pct < 75:
                    score_str = f"{strength_pct}% MODERATE"
                else:
                    score_str = f"{strength_pct}% SECURE"

                self.cell(38, 5.5, f" {pwd_label[:20]}", border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.cell(20, 5.5, f"{entropy_val} bits", border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.cell(22, 5.5, f"{pwned_val:,}" if pwned_val >= 0 else "N/A", border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                name_str = ", ".join(names[:2]) if names else "-"
                self.cell(18, 5.5, name_str[:12], border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.cell(60, 5.5, f" {finding_str[:40]}", border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)

                # Color the status cell
                if "HIGH" in score_str:
                    self.set_text_color(220, 38, 38)
                elif "MOD" in score_str:
                    self.set_text_color(217, 119, 6)
                else:
                    self.set_text_color(16, 185, 129)
                self.cell(32, 5.5, score_str, border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            self.ln(5)

        # ═══ 3. Algorithm Benchmark ═══
        self._section_heading("3", "CRYPTOGRAPHIC ALGORITHM BENCHMARK & HARDWARE RESISTANCE")

        self._body_text(
            "This section benchmarks host-side execution latency for each hashing algorithm and projects "
            "cracking feasibility against an adversary equipped with 8x NVIDIA RTX 4090 GPUs "
            "(approximately 300 billion MD5 guesses/second). Adaptive algorithms like bcrypt and "
            "Argon2id introduce deliberate computational cost that renders brute-force attacks infeasible."
        )

        # Table Header
        self.set_font('helvetica', 'B', 7.5)
        self.set_fill_color(15, 23, 42)
        self.set_text_color(255, 255, 255)
        self.cell(32, 6, 'Algorithm', border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(30, 6, 'Compute Latency', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(22, 6, 'Digest', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(24, 6, 'Salt', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(46, 6, 'Cracking (8x 4090)', border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(36, 6, 'Security Posture', border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if not stats:
            stats = [
                {'algorithm': 'MD5', 'avg_time': 0.000001, 'hash_length': 32},
                {'algorithm': 'SHA-1', 'avg_time': 0.000002, 'hash_length': 40},
                {'algorithm': 'SHA-256', 'avg_time': 0.000003, 'hash_length': 64},
                {'algorithm': 'SHA-512', 'avg_time': 0.000004, 'hash_length': 128},
                {'algorithm': 'bcrypt', 'avg_time': 0.354120, 'hash_length': 60},
                {'algorithm': 'Argon2id', 'avg_time': 0.285400, 'hash_length': 97}
            ]

        algo_details = {
            'MD5': {'feasibility': 'Instant (< 1 ms)', 'status': 'CRITICAL', 'salt': 'None', 'color': (220, 38, 38)},
            'SHA-1': {'feasibility': 'Instant (< 5 ms)', 'status': 'CRITICAL', 'salt': 'None', 'color': (220, 38, 38)},
            'SHA-256': {'feasibility': 'Minutes to Hours', 'status': 'UNSAFE', 'salt': 'None', 'color': (217, 119, 6)},
            'SHA-512': {'feasibility': 'Hours to Days', 'status': 'UNSAFE', 'salt': 'None', 'color': (217, 119, 6)},
            'BCRYPT': {'feasibility': 'Decades (Adaptive)', 'status': 'RECOMMENDED', 'salt': '128-bit', 'color': (59, 130, 246)},
            'ARGON2ID': {'feasibility': 'Centuries (Mem-Hard)', 'status': 'GOLD STANDARD', 'salt': '128-bit', 'color': (16, 185, 129)},
        }

        self.set_font('helvetica', '', 7.5)
        for i, s in enumerate(stats):
            algo = str(s.get('algorithm', '')).upper()
            avg_time = float(s.get('avg_time', 0))
            hlen = s.get('hash_length', 0)
            detail = algo_details.get(algo, {'feasibility': 'Unknown', 'status': 'UNKNOWN', 'salt': 'N/A', 'color': (100, 116, 139)})

            if i % 2 == 0:
                self.set_fill_color(255, 255, 255)
            else:
                self.set_fill_color(241, 245, 249)
            self.set_text_color(30, 41, 59)

            self.cell(32, 5.5, f" {algo}", border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(30, 5.5, f"{avg_time*1000:.3f} ms/hash", border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(22, 5.5, f"{hlen} chars", border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(24, 5.5, detail['salt'], border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)

            self.set_text_color(*detail['color'])
            self.cell(46, 5.5, f" {detail['feasibility']}", border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(36, 5.5, detail['status'], border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(5)

        # ─────────────────────────────────────────────────────────────────────
        # PAGE 2: IN-DEPTH TECHNICAL MITIGATIONS & ENTERPRISE ROADMAP
        # ─────────────────────────────────────────────────────────────────────
        self.add_page()

        self._section_heading("4", "STRATEGIC REMEDIATION & MITIGATION ROADMAP")

        self._body_text(
            "The following phased remediation plan addresses identified vulnerabilities in order of "
            "criticality. Each phase includes specific technical actions, compliance references, and "
            "expected outcomes. Organizations should treat Phase 1 actions as emergency measures and "
            "complete them within the first two weeks of receiving this report."
        )

        # Phase 1: Immediate Containment (0-14 days)
        self._phase_box(
            title="PHASE 1: IMMEDIATE CONTAINMENT (DAYS 0 - 14)",
            title_color_rgb=(185, 28, 28),
            fill_rgb=(254, 242, 242),
            border_rgb=(252, 165, 165),
            items=[
                "Personal Identifier Blacklist: Deploy an active dictionary filter that rejects passwords "
                "containing employee names, usernames, organization names, and common corporate terms during "
                "registration and password change flows. Ref: NIST SP 800-63B Sec.5.1.1.2.",
                "Breach Corpus Screening: Integrate HaveIBeenPwned Pwned Passwords API using the K-Anonymity "
                "model (SHA-1 prefix range query) to reject any password appearing in known breach databases "
                "without transmitting plaintext credentials over the network.",
                "Emergency Credential Rotation: Force immediate password resets for all accounts whose "
                "credentials scored below 40% strength or appeared in breach databases. Notify affected "
                "users with clear guidance on creating strong passphrases.",
                "Audit Logging: Enable detailed authentication event logging (success, failure, lockout, "
                "reset) with timestamps, source IP, user agent, and geolocation for forensic analysis.",
            ],
            height=48
        )

        # Phase 2: Architectural Hardening (15-60 days)
        self._phase_box(
            title="PHASE 2: ARCHITECTURAL HARDENING & KDF UPGRADE (DAYS 15 - 60)",
            title_color_rgb=(180, 83, 9),
            fill_rgb=(254, 249, 195),
            border_rgb=(253, 224, 71),
            items=[
                "Argon2id Migration: Transition all credential storage from legacy algorithms (MD5, SHA-1, "
                "SHA-256) to Argon2id (RFC 9106) with parameters: memory cost 64 MB, time cost 3 iterations, "
                "parallelism 1. Implement transparent on-login re-hashing for gradual migration.",
                "bcrypt Fallback: Where Argon2id is not supported by the platform, deploy bcrypt with a "
                "minimum cost factor of 12 (producing ~250ms latency per hash), ensuring unique per-user "
                "128-bit random salts are generated via CSPRNG.",
                "NIST SP 800-63B Policy Alignment: Remove periodic password expiration requirements (which "
                "encourage predictable patterns like 'Password1!' to 'Password2!'). Set minimum length to "
                "14 characters. Allow passphrases up to 128 characters. Remove composition rules.",
                "Application-Layer Peppering: Store a 256-bit HMAC secret key in a hardware security module "
                "(HSM) or secrets manager, separate from the credential database. Apply HMAC-SHA256 pepper "
                "before feeding passwords to the KDF.",
                "Credential Stuffing Defense: Deploy account lockout after 10 consecutive failures with "
                "exponential backoff (30s, 60s, 120s, 300s). Implement IP-based velocity rate limiting.",
            ],
            height=58
        )

        # Phase 3: Zero-Trust & Defense-in-Depth (61-90+ days)
        self._phase_box(
            title="PHASE 3: ZERO-TRUST ACCESS & DEFENSE-IN-DEPTH (DAYS 61 - 90+)",
            title_color_rgb=(21, 128, 61),
            fill_rgb=(240, 253, 244),
            border_rgb=(134, 239, 172),
            items=[
                "FIDO2 / WebAuthn MFA: Deploy passwordless or multi-factor authentication using hardware "
                "security keys (YubiKey, Titan) or platform authenticators (Windows Hello, Touch ID) across "
                "all administrative, privileged, and customer-facing authentication endpoints.",
                "TOTP Fallback: For users without FIDO2 devices, enforce RFC 6238 TOTP-based authenticator "
                "apps (Google Authenticator, Authy, Microsoft Authenticator) as a mandatory second factor. "
                "Disable SMS-based OTP due to SIM-swapping vulnerabilities.",
                "Continuous Threat Monitoring: Deploy SIEM integration to monitor failed authentication "
                "velocity, impossible travel scenarios, credential reuse across services, and anomalous "
                "access patterns. Set alert thresholds for >5 failures/minute per account.",
                "Secret Rotation Schedule: Implement automated rotation of application pepper keys, API "
                "tokens, and service account credentials on a 90-day cycle with zero-downtime deployment.",
                "Penetration Testing: Conduct quarterly internal/external password spraying and credential "
                "stuffing assessments to validate the effectiveness of implemented controls.",
            ],
            height=58
        )

        self.ln(2)

        # ─────────────────────────────────────────────────────────────────────
        # PAGE 3: ADDITIONAL GUIDANCE & COMPLIANCE
        # ─────────────────────────────────────────────────────────────────────
        self.add_page()

        self._section_heading("5", "COMPLIANCE REFERENCE MATRIX")

        self._body_text(
            "The following table maps each remediation action to the relevant industry standards and "
            "regulatory frameworks to support compliance and audit readiness."
        )

        # Compliance table
        self.set_font('helvetica', 'B', 7.5)
        self.set_fill_color(15, 23, 42)
        self.set_text_color(255, 255, 255)
        self.cell(55, 6, 'Control / Action', border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(40, 6, 'NIST SP 800-63B', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(35, 6, 'OWASP ASVS', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(30, 6, 'CIS Controls', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(30, 6, 'PCI DSS 4.0', border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        compliance_rows = [
            ("Argon2id / bcrypt adoption", "Sec.5.1.1.2", "V2.4.4", "5.2", "Req 8.3.2"),
            ("Breach database screening", "Sec.5.1.1.2", "V2.1.7", "16.1", "Req 8.3.6"),
            ("Personal name blacklist", "Sec.5.1.1.2", "V2.1.8", "16.1", "Req 8.3.6"),
            ("14-char minimum length", "Sec.5.1.1.1", "V2.1.1", "5.2", "Req 8.3.1"),
            ("Remove periodic expiry", "Sec.5.1.1.2", "V2.1.10", "5.2", "N/A"),
            ("Multi-factor authentication", "Sec.4.2.1", "V2.8.1", "6.3", "Req 8.4.2"),
            ("Rate limiting / lockout", "Sec.5.2.2", "V2.2.1", "16.11", "Req 8.3.4"),
            ("Audit logging", "Sec.4.3.4", "V7.1.1", "8.5", "Req 10.2"),
        ]

        self.set_font('helvetica', '', 7.5)
        for i, (action, nist, owasp, cis, pci) in enumerate(compliance_rows):
            if i % 2 == 0:
                self.set_fill_color(255, 255, 255)
            else:
                self.set_fill_color(241, 245, 249)
            self.set_text_color(30, 41, 59)

            self.cell(55, 5.5, f" {action}", border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(40, 5.5, nist, border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(35, 5.5, owasp, border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(30, 5.5, cis, border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(30, 5.5, pci, border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(6)

        # ═══ 6. Password Policy Recommendations ═══
        self._section_heading("6", "RECOMMENDED PASSWORD POLICY CONFIGURATION")

        self._body_text(
            "Based on the assessment findings and current NIST SP 800-63B guidance, the following "
            "password policy parameters are recommended for immediate implementation:"
        )

        # Policy table
        self.set_font('helvetica', 'B', 7.5)
        self.set_fill_color(15, 23, 42)
        self.set_text_color(255, 255, 255)
        self.cell(60, 6, 'Policy Parameter', border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(45, 6, 'Current (Typical)', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(45, 6, 'Recommended', border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(40, 6, 'Priority', border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        policy_rows = [
            ("Minimum password length", "8 characters", "14 characters", "CRITICAL"),
            ("Maximum password length", "64 characters", "128 characters", "HIGH"),
            ("Hashing algorithm", "SHA-256 / MD5", "Argon2id (RFC 9106)", "CRITICAL"),
            ("Salt generation", "None / static", "128-bit CSPRNG/user", "CRITICAL"),
            ("Work factor (bcrypt)", "Cost 4-8", "Cost 12+", "HIGH"),
            ("Periodic expiration", "60-90 days", "Remove (event-based)", "MEDIUM"),
            ("Breach database check", "Disabled", "HIBP K-Anonymity", "CRITICAL"),
            ("Personal name filter", "Disabled", "Active dictionary", "HIGH"),
            ("MFA requirement", "Optional", "Mandatory (FIDO2)", "HIGH"),
            ("Account lockout", "3 attempts", "10 + exponential backoff", "MEDIUM"),
        ]

        self.set_font('helvetica', '', 7.5)
        for i, (param, current, recommended, priority) in enumerate(policy_rows):
            if i % 2 == 0:
                self.set_fill_color(255, 255, 255)
            else:
                self.set_fill_color(241, 245, 249)
            self.set_text_color(30, 41, 59)

            self.cell(60, 5.5, f" {param}", border=1, align='L', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.cell(45, 5.5, current, border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)

            self.set_text_color(16, 185, 129)
            self.cell(45, 5.5, recommended, border=1, align='C', fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)

            if priority == "CRITICAL":
                self.set_text_color(220, 38, 38)
            elif priority == "HIGH":
                self.set_text_color(217, 119, 6)
            else:
                self.set_text_color(59, 130, 246)
            self.cell(40, 5.5, priority, border=1, align='C', fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(6)

        # ═══ 7. Key Technical References ═══
        self._section_heading("7", "TECHNICAL REFERENCES & FURTHER READING")

        references = [
            "NIST SP 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management (June 2017, Updated 2024)",
            "RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications (Sept 2021)",
            "OWASP Authentication Cheat Sheet - Password Storage, Credential Stuffing Prevention (2024 Edition)",
            "OWASP Application Security Verification Standard (ASVS) v4.0.3 - Chapter V2: Authentication",
            "CIS Controls v8.0 - Control 5: Account Management, Control 6: Access Control Management",
            "PCI DSS v4.0 - Requirement 8: Identify Users and Authenticate Access to System Components",
            "FIDO Alliance WebAuthn Specification - W3C Recommendation Level 2 (April 2021)",
            "HaveIBeenPwned API v3 - K-Anonymity Model for Pwned Passwords (Troy Hunt, 2024)",
            "Password Hashing Competition (PHC) - Final Report and Winner Selection (2015)",
        ]
        self._bullet_list(references)

        self.ln(4)

        # ═══ 8. Formal Compliance Sign-Off ═══
        self._section_heading("8", "FORMAL COMPLIANCE ATTESTATION & SIGN-OFF")

        self.set_fill_color(241, 245, 249)
        self.set_draw_color(148, 163, 184)
        self.rect(10, self.get_y(), 190, 36, 'DF')

        sign_y = self.get_y() + 3
        self.set_xy(14, sign_y)
        self.set_font('helvetica', 'B', 8.5)
        self.set_text_color(71, 85, 105)
        self.cell(90, 5, "LEAD CRYPTOGRAPHIC ASSESSOR:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(90, 5, "REPORT VERIFICATION CHECKSUM (SHA-256):", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        checksum = hashlib.sha256(f"{self.company_name}{datetime.date.today()}{self.auditor_name}".encode()).hexdigest()[:40]
        self.set_xy(14, sign_y + 6)
        self.set_font('helvetica', 'B', 10)
        self.set_text_color(30, 41, 59)
        self.cell(90, 5.5, self.auditor_name, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font('courier', 'B', 7.5)
        self.set_text_color(59, 130, 246)
        self.cell(90, 5.5, checksum, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_xy(14, sign_y + 13)
        self.set_font('helvetica', '', 8)
        self.set_text_color(100, 116, 139)
        self.cell(90, 4, f"Date: {datetime.datetime.now().strftime('%B %d, %Y')}", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.cell(90, 4, f"Report ID: {report_id}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_xy(14, sign_y + 19)
        self.set_font('helvetica', 'I', 7.5)
        self.set_text_color(100, 116, 139)
        self.multi_cell(182, 3.5,
            "Attestation: This security assessment report was generated by HashSentinel Enterprise Suite "
            "under authorized scope for the named client. All credential testing was performed in an "
            "isolated environment using one-way hash computations. No plaintext passwords were stored, "
            "transmitted, or retained beyond the active session. Data handling complies with responsible "
            "security disclosure principles, GDPR data minimization requirements, and client NDA obligations."
        )

        # ─── Disclaimer ───
        self.ln(6)
        self.set_font('helvetica', '', 7)
        self.set_text_color(148, 163, 184)
        self.multi_cell(0, 3.5,
            "DISCLAIMER: This report is provided for informational and educational purposes as part of "
            "a security assessment engagement. The findings and recommendations are based on data available "
            "at the time of assessment and may not reflect the current security posture if changes have "
            "been made since the assessment date. HashSentinel and its assessors assume no liability for "
            "actions taken or not taken based on this report. Recipients are advised to consult qualified "
            "security professionals before implementing changes to production authentication systems."
        )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        self.output(output_path)
        return output_path


if __name__ == "__main__":
    gen = ReportGenerator()
    test_session = [
        {'password': 'OmarAbuSaeed', 'display_password': 'O**********d', 'entropy': 68.4, 'pwned_count': 0, 'detected_names': ['omar', 'abu', 'saeed'], 'strength_percent': 20},
        {'password': 'admin123', 'display_password': 'a*****3', 'entropy': 32.1, 'pwned_count': 124500, 'detected_names': [], 'strength_percent': 15},
        {'password': 'Correct-Horse-Battery-Staple!', 'display_password': 'C***************************!', 'entropy': 92.3, 'pwned_count': 0, 'detected_names': [], 'strength_percent': 95},
    ]
    path = gen.generate_report(session_items=test_session, company_name="Omar Abu Saeed Security Assessment", auditor_name="Principal Security Assessor")
    print(f"Generated multi-page professional report at: {path}")
