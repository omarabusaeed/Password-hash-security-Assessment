import zxcvbn
import requests
import hashlib
import argparse
import logging
import math
import re
import secrets
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Fallback core names & dictionary list
CORE_COMMON_NAMES = [
    "omar", "abu", "saeed", "ali", "ahmed", "mohammed", "muhammad", "ahmad", "fatima", "hassan",
    "hussein", "aisha", "zayd", "hamza", "ibrahim", "tariq", "yousef", "mustafa", "bilal", "khaled",
    "rashid", "salman", "faisal", "nasir", "karim", "samir", "nabil", "jamal", "farhan", "imran",
    "rahul", "priya", "rohit", "ankit", "pooja", "amit", "deepak", "neha", "sunil", "ravi",
    "ajay", "sanjay", "manoj", "vikas", "anil", "suresh", "rajesh", "ramesh", "dinesh", "mukesh",
    "patel", "sharma", "kumar", "singh", "gupta", "khan", "sheikh", "syed", "malik", "qureshi",
    "john", "david", "james", "robert", "michael", "william", "richard", "joseph", "thomas", "charles",
    "daniel", "matthew", "anthony", "donald", "mark", "paul", "steven", "andrew", "kenneth", "joshua",
    "kevin", "brian", "george", "edward", "ronald", "timothy", "jason", "jeffrey", "ryan", "jacob",
    "gary", "nicholas", "eric", "jonathan", "stephen", "larry", "justin", "scott", "brandon", "benjamin",
    "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "susan", "jessica", "sarah", "karen",
    "admin", "administrator", "root", "user", "guest", "system", "login", "test", "demo", "secret",
    "pass", "password", "master", "welcome", "access", "security", "server", "shadow", "dragon", "monkey",
    "football", "superman", "summer", "winter", "spring", "autumn", "london", "paris", "tokyo", "newyork"
]

# Curated wordlist for generating memorable, high-entropy passphrases (Diceware-inspired)
SECURITY_WORDS = [
    "orbit", "shield", "cipher", "matrix", "vector", "falcon", "beacon", "cobalt",
    "vertex", "zenith", "timber", "shadow", "quasar", "pulsar", "nexus", "prism",
    "granite", "aurora", "vortex", "solstice", "canyon", "harbor", "delta", "frost",
    "silver", "glacier", "phoenix", "summit", "cascade", "horizon", "sierra", "bastion"
]

class StrengthAnalyzer:
    def __init__(self, names_file_path=None):
        self.hibp_url = "https://api.pwnedpasswords.com/range/"
        self.common_names = set(CORE_COMMON_NAMES)
        
        # Load external extended dictionary file if present
        if names_file_path is None:
            # Try finding data/common_names.txt
            curr_dir = os.path.dirname(os.path.abspath(__file__))
            cand_path = os.path.join(curr_dir, '..', 'data', 'common_names.txt')
            if os.path.exists(cand_path):
                names_file_path = cand_path

        if names_file_path and os.path.exists(names_file_path):
            try:
                with open(names_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        w = line.strip().lower()
                        if len(w) >= 3:
                            self.common_names.add(w)
            except Exception as e:
                logger.warning(f"Could not load custom names file: {e}")

    def detect_personal_names(self, password):
        """
        Check if password contains any common first name, surname, or dictionary word.
        Returns list of matched terms.
        """
        if not password:
            return []
        
        pwd_clean = re.sub(r'[^a-zA-Z]', '', password).lower()
        pwd_raw = password.lower()
        
        matches = []
        for name in self.common_names:
            if len(name) < 3:
                continue
            # Exact match or substring match
            if name in pwd_clean or name in pwd_raw:
                matches.append(name)
        
        # Sort by length descending so longest matched name comes first
        matches.sort(key=len, reverse=True)
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                deduped.append(m)
        return deduped

    def check_hibp(self, password):
        """Check if password has been pwned using k-anonymity model."""
        if not password:
            return 0
        sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_pwd[:5]
        suffix = sha1_pwd[5:]
        
        try:
            response = requests.get(self.hibp_url + prefix, timeout=4)
            if response.status_code != 200:
                return 0
            
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
            return 0
        except Exception as e:
            logger.warning(f"HIBP check offline or timed out: {e}")
            return -1

    def calculate_entropy(self, password):
        """Calculate pool-based password entropy in bits."""
        if not password:
            return 0.0
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset_size += 33
        
        if charset_size == 0: 
            return 0.0
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)

    def calculate_shannon_entropy(self, password):
        """Calculate Shannon entropy based on symbol frequency."""
        if not password:
            return 0.0
        length = len(password)
        freq = {}
        for c in password:
            freq[c] = freq.get(c, 0) + 1
        shannon = 0.0
        for count in freq.values():
            p = count / length
            shannon -= p * math.log2(p)
        return round(shannon * length, 2)

    def get_charset_metrics(self, password):
        """Return breakdown of character diversity and composition."""
        return {
            'length': len(password),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_digit': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'lower_count': len(re.findall(r'[a-z]', password)),
            'upper_count': len(re.findall(r'[A-Z]', password)),
            'digit_count': len(re.findall(r'[0-9]', password)),
            'special_count': len(re.findall(r'[^a-zA-Z0-9]', password)),
            'unique_chars': len(set(password)),
            'repetition_ratio': round(1.0 - (len(set(password)) / max(len(password), 1)), 2)
        }

    def evaluate_nist_compliance(self, password, pwned_count=0, detected_names=None):
        """Evaluate password against NIST SP 800-63B guidelines."""
        if detected_names is None:
            detected_names = []
            
        checks = []
        length = len(password)
        
        # Rule 1: Length >= 8 (mandatory), >= 12 (recommended)
        checks.append({
            'rule': 'Minimum Length (>= 8 chars)',
            'status': 'PASS' if length >= 8 else 'FAIL',
            'detail': f'Length is {length} characters. NIST requires minimum 8 for user-chosen passwords.'
        })
        checks.append({
            'rule': 'Enterprise Length Standard (>= 14 chars)',
            'status': 'PASS' if length >= 14 else ('WARNING' if length >= 10 else 'FAIL'),
            'detail': 'Recommended enterprise password/passphrase length is 14+ characters.'
        })
        
        # Rule 2: Breach check (K-Anonymity)
        if pwned_count > 0:
            checks.append({
                'rule': 'Breach Corpus Exclusion (HIBP)',
                'status': 'FAIL',
                'detail': f'Password appeared in {pwned_count:,} public data breach leaks.'
            })
        elif pwned_count == 0:
            checks.append({
                'rule': 'Breach Corpus Exclusion (HIBP)',
                'status': 'PASS',
                'detail': 'Password not detected in known public compromised credential dumps.'
            })
        else:
            checks.append({
                'rule': 'Breach Corpus Exclusion (HIBP)',
                'status': 'UNKNOWN',
                'detail': 'Breach database API currently unreachable.'
            })
            
        # Rule 3: Personal Name & Dictionary Check
        if detected_names:
            checks.append({
                'rule': 'Personal Name & Dictionary Exclusion',
                'status': 'FAIL',
                'detail': f'Contains personal identifier or dictionary name: "{", ".join(detected_names[:3])}".'
            })
        else:
            checks.append({
                'rule': 'Personal Name & Dictionary Exclusion',
                'status': 'PASS',
                'detail': 'No common personal names or dictionary terms detected.'
            })

        # Rule 4: Repetitive or sequential strings
        has_seq = bool(re.search(r'(.)\1{2,}', password)) or ("123" in password) or ("abc" in password.lower())
        checks.append({
            'rule': 'Pattern & Sequential Repetition',
            'status': 'FAIL' if has_seq else 'PASS',
            'detail': 'Avoid sequences like 123, abc, or 3+ repeated identical characters.' if has_seq else 'No obvious repetitive or sequential patterns detected.'
        })
        
        passes = sum(1 for c in checks if c['status'] == 'PASS')
        total = len(checks)
        score_pct = int((passes / total) * 100)
        return {
            'compliance_score': score_pct,
            'checks': checks,
            'is_compliant': length >= 8 and pwned_count == 0 and not has_seq and not detected_names
        }

    def generate_passphrase(self, word_count=4):
        """Generate a cryptographically secure memorable passphrase (Diceware style)."""
        chosen = [secrets.choice(SECURITY_WORDS) for _ in range(word_count)]
        chosen = [w.capitalize() if i == 0 else w for i, w in enumerate(chosen)]
        separator = "-"
        suffix_num = str(secrets.randbelow(90) + 10)
        suffix_sym = secrets.choice(["!", "@", "#", "$", "%"])
        passphrase = separator.join(chosen) + suffix_sym + suffix_num
        return passphrase

    def generate_random_token(self, length=18):
        """Generate an ultra-high-entropy random alphanumeric + symbol string."""
        alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*+="
        token = "".join(secrets.choice(alphabet) for _ in range(length - 1))
        token += secrets.choice(["!", "@", "#", "$", "%"])
        return token

    def suggest_alternative(self, password):
        """Suggest a stronger alternative."""
        alt = self.generate_passphrase(word_count=4)
        if len(alt) <= len(password):
            alt = self.generate_random_token(length=max(len(password) + 6, 18))
        return alt

    def get_smart_alternatives(self, password):
        """Return dual high-grade alternative suggestions with entropy analysis."""
        passphrase = self.generate_passphrase(word_count=4)
        random_token = self.generate_random_token(length=max(len(password) + 4, 18))
        return {
            'passphrase': {
                'value': passphrase,
                'entropy': self.calculate_entropy(passphrase),
                'type': 'NIST Multi-Word Passphrase',
                'description': 'High human memorability, extreme resistance against dictionary & brute-force attacks.'
            },
            'token': {
                'value': random_token,
                'entropy': self.calculate_entropy(random_token),
                'type': 'Cryptographic Random Token',
                'description': 'Maximum mathematical entropy per character; ideal for password managers and API keys.'
            }
        }

    def estimate_hardware_crack_times(self, entropy_bits, name_detected=False):
        """Calculate realistic crack times across various threat actor compute capabilities."""
        if name_detected:
            # Targeted dictionary attack cracks names in milliseconds
            return [
                {'tier': 'Targeted Adversary (OSINT Dictionary)', 'specs': 'CewL / Custom Wordlist', 'time_fast_hash': '< 1 millisecond', 'time_bcrypt': '< 0.5 seconds', 'time_argon2': '< 2 seconds'},
                {'tier': 'Commodity Laptop (Single CPU)', 'specs': '8-core Intel / Apple M-series', 'time_fast_hash': '< 1 second', 'time_bcrypt': '< 5 seconds', 'time_argon2': '< 10 seconds'},
                {'tier': 'Consumer GPU (1x RTX 4090)', 'specs': 'NVIDIA Ada Lovelace 24GB', 'time_fast_hash': 'Instant', 'time_bcrypt': 'Instant', 'time_argon2': 'Instant'},
                {'tier': 'Professional Cracking Rig (8x RTX 4090)', 'specs': 'Enterprise Hashcat Cluster', 'time_fast_hash': 'Instant', 'time_bcrypt': 'Instant', 'time_argon2': 'Instant'}
            ]

        keyspace = 2 ** max(1.0, float(entropy_bits))
        half_keyspace = keyspace / 2.0

        tiers = [
            {'tier': 'Commodity Laptop (Single CPU)', 'specs': '8-core Intel / Apple M-series', 'fast_rate': 2.5e7, 'bcrypt_rate': 4.0e2, 'argon2_rate': 10.0},
            {'tier': 'Consumer GPU (1x RTX 4090)', 'specs': 'NVIDIA Ada Lovelace 24GB', 'fast_rate': 4.5e10, 'bcrypt_rate': 1.8e5, 'argon2_rate': 2.5e3},
            {'tier': 'Professional Cracking Rig (8x RTX 4090)', 'specs': 'Enterprise Hashcat Cluster', 'fast_rate': 3.6e11, 'bcrypt_rate': 1.5e6, 'argon2_rate': 2.0e4},
            {'tier': 'State-Level Cloud Farm / Botnet', 'specs': 'Distributed 1,000+ Enterprise GPUs', 'fast_rate': 5.0e13, 'bcrypt_rate': 2.0e8, 'argon2_rate': 2.5e6}
        ]

        def format_time(seconds):
            if seconds < 0.001: return "< 1 millisecond"
            elif seconds < 1.0: return f"{int(seconds * 1000)} ms"
            elif seconds < 60: return f"{round(seconds, 1)} seconds"
            elif seconds < 3600: return f"{round(seconds / 60, 1)} minutes"
            elif seconds < 86400: return f"{round(seconds / 3600, 1)} hours"
            elif seconds < 31536000: return f"{round(seconds / 86400, 1)} days"
            elif seconds < 3.1536e9: return f"{round(seconds / 31536000, 1)} years"
            elif seconds < 3.1536e12: return f"{round(seconds / 3.1536e9, 1)} thousand years"
            elif seconds < 3.1536e15: return f"{round(seconds / 3.1536e12, 1)} million years"
            else: return "1+ Billion Years (Practically Uncrackable)"

        projections = []
        for t in tiers:
            sec_fast = half_keyspace / t['fast_rate']
            sec_bcrypt = half_keyspace / t['bcrypt_rate']
            sec_argon2 = half_keyspace / t['argon2_rate']
            projections.append({
                'tier': t['tier'],
                'specs': t['specs'],
                'time_fast_hash': format_time(sec_fast),
                'time_bcrypt': format_time(sec_bcrypt),
                'time_argon2': format_time(sec_argon2)
            })
        return projections

    def analyze(self, password):
        """Perform comprehensive analysis of a password."""
        # Detect personal names or common words
        detected_names = self.detect_personal_names(password) if password else []
        
        # Use zxcvbn with user inputs
        results = zxcvbn.zxcvbn(password, user_inputs=detected_names) if password else {
            'score': 0, 'crack_times_display': {}, 'feedback': {'suggestions': [], 'warning': ''}
        }
        
        entropy = self.calculate_entropy(password)
        shannon = self.calculate_shannon_entropy(password)
        metrics = self.get_charset_metrics(password)
        pwned_count = self.check_hibp(password) if password else 0
        
        score = results.get('score', 0)
        base_pct = int((score / 4.0) * 100)
        
        # Penalties:
        # 1. If personal name or dictionary term detected: severe penalty!
        if detected_names:
            base_pct = min(20, base_pct)
            score = min(1, score)
        
        # 2. If pwned in breach: severe penalty!
        if pwned_count > 0:
            strength_pct = min(15, base_pct)
        elif len(password) < 8:
            strength_pct = min(30, base_pct)
        else:
            strength_pct = base_pct

        nist_audit = self.evaluate_nist_compliance(password, pwned_count, detected_names)
        hardware_estimates = self.estimate_hardware_crack_times(entropy, name_detected=bool(detected_names))
        smart_alts = self.get_smart_alternatives(password) if password else {}

        # Curate feedback & warnings
        suggestions = list(results.get('feedback', {}).get('suggestions', []))
        warning = results.get('feedback', {}).get('warning', '')
        
        if detected_names:
            names_str = ", ".join(detected_names[:3])
            warning = f"CRITICAL VULNERABILITY: Contains personal name or common identifier ('{names_str}'). Attackers routinely scrape names from social media and email handles to generate targeted wordlists (CewL/Cupp), cracking this in seconds."
            suggestions = [
                f"Remove the name '{names_str}' entirely from your password.",
                "Use a 4-word random passphrase like 'Cobalt-Beacon-Orbit-Falcon!8' instead."
            ]
        elif pwned_count > 0:
            warning = f"CRITICAL HAZARD: Found in {pwned_count:,} public data breaches! Discontinue use immediately."
            suggestions = ["This password is known to hackers worldwide. Replace it immediately."]
        elif not suggestions:
            if strength_pct >= 80:
                suggestions = ["Excellent cryptographic strength.", "Meets enterprise authentication standards."]
            elif strength_pct >= 50:
                suggestions = ["Consider increasing character length.", "Use a 4-word passphrase for higher entropy."]
            else:
                suggestions = ["Password is too predictable or short.", "Vulnerable to rapid offline cracking."]

        analysis = {
            'password': password,
            'score': score,
            'strength_percent': strength_pct,
            'entropy': entropy,
            'shannon_entropy': shannon,
            'detected_names': detected_names,
            'metrics': metrics,
            'crack_time_estimates': results.get('crack_times_display', {}),
            'hardware_estimates': hardware_estimates,
            'pwned_count': pwned_count,
            'feedback': suggestions,
            'warning': warning,
            'nist_audit': nist_audit,
            'smart_alternatives': smart_alts
        }
        return analysis

def main():
    analyzer = StrengthAnalyzer()
    for test_pwd in ["OmarAbuSaeed", "admin123", "password", "S3cur3#P@ssw0rd!"]:
        res = analyzer.analyze(test_pwd)
        print(f"\nPassword: {test_pwd}")
        print(f"Strength Score: {res['score']}/4 ({res['strength_percent']}%)")
        print(f"Detected Names: {res['detected_names']}")
        print(f"Warning: {res['warning']}")

if __name__ == "__main__":
    main()
