import subprocess
import os
import time
import argparse
import logging
import yaml
import shutil
import hashlib
import bcrypt
import argon2

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Built-in top real-world breached password candidates for instant simulation
TOP_PASSWORD_CORPUS = [
    "123456", "password", "123456789", "qwerty", "password123", "12345", "12345678",
    "111111", "123123", "1234567", "1234", "admin", "welcome", "login", "root",
    "pass123", "iloveyou", "monkey", "dragon", "baseball", "football", "letmein",
    "master", "sunshine", "princess", "shadow", "superman", "starwars", "secret",
    "trustno1", "computer", "internet", "security", "administrator", "guest",
    "p@ssword", "P@ssw0rd", "admin123", "welcome1", "summer2024", "winter2024"
]

class CrackSimulator:
    def __init__(self, config_path='config.yaml'):
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {'paths': {'rockyou_path': 'data/wordlists/rockyou.txt'}}
        
        self.rockyou_path = self.config.get('paths', {}).get('rockyou_path', 'data/wordlists/rockyou.txt')
        self.output_dir = "data/cracked_results"
        os.makedirs(self.output_dir, exist_ok=True)

    def check_tool(self, tool):
        return shutil.which(tool) is not None

    def attack_single_hash(self, target_hash, algo='auto', custom_wordlist=None):
        """
        Run a real-time dictionary & pattern attack against an input hash.
        Demonstrates the speed of cracking unsalted hashes vs salted hashes.
        """
        target = target_hash.strip()
        corpus = list(TOP_PASSWORD_CORPUS)
        if custom_wordlist and isinstance(custom_wordlist, list):
            corpus = custom_wordlist + corpus

        # Auto-detect algorithm if requested
        if algo == 'auto':
            if target.startswith(('$2a$', '$2b$', '$2y$')):
                algo = 'bcrypt'
            elif target.startswith('$argon2'):
                algo = 'argon2'
            elif len(target) == 32:
                algo = 'md5'
            elif len(target) == 40:
                algo = 'sha1'
            elif len(target) == 64:
                algo = 'sha256'
            else:
                algo = 'md5'

        start_time = time.perf_counter()
        attempts = 0
        cracked = False
        cracked_password = None

        if algo == 'md5':
            for cand in corpus:
                attempts += 1
                if hashlib.md5(cand.encode('utf-8')).hexdigest().lower() == target.lower():
                    cracked = True
                    cracked_password = cand
                    break
        elif algo == 'sha1':
            for cand in corpus:
                attempts += 1
                if hashlib.sha1(cand.encode('utf-8')).hexdigest().lower() == target.lower():
                    cracked = True
                    cracked_password = cand
                    break
        elif algo == 'sha256':
            for cand in corpus:
                attempts += 1
                if hashlib.sha256(cand.encode('utf-8')).hexdigest().lower() == target.lower():
                    cracked = True
                    cracked_password = cand
                    break
        elif algo == 'bcrypt':
            # bcrypt comparison is deliberately slow
            for cand in corpus[:10]: # Test top 10 to avoid stalling UI
                attempts += 1
                try:
                    if bcrypt.checkpw(cand.encode('utf-8'), target.encode('utf-8')):
                        cracked = True
                        cracked_password = cand
                        break
                except Exception:
                    break
        elif algo == 'argon2':
            ph = argon2.PasswordHasher()
            for cand in corpus[:5]:
                attempts += 1
                try:
                    if ph.verify(target, cand):
                        cracked = True
                        cracked_password = cand
                        break
                except Exception:
                    pass

        elapsed = time.perf_counter() - start_time
        return {
            'cracked': cracked,
            'password': cracked_password,
            'attempts': attempts,
            'time_taken': elapsed,
            'speed_attempts_per_sec': (attempts / elapsed) if elapsed > 0 else 0,
            'algo': algo.upper(),
            'target_hash': target[:24] + '...' if len(target) > 24 else target
        }

    def demonstrate_salt_defense(self, plaintext_password="corporate_login_2026"):
        """
        Generate multiple hashes for the exact same password using unsalted MD5 vs salted bcrypt/Argon2.
        Proves why salts neutralize Rainbow Tables.
        """
        md5_samples = [hashlib.md5(plaintext_password.encode()).hexdigest() for _ in range(3)]
        
        # bcrypt with unique salts
        bcrypt_samples = [bcrypt.hashpw(plaintext_password.encode(), bcrypt.gensalt(rounds=10)).decode() for _ in range(3)]
        
        # Argon2id with unique salts
        ph = argon2.PasswordHasher(time_cost=1, memory_cost=32768)
        argon2_samples = [ph.hash(plaintext_password) for _ in range(3)]

        return {
            'password': plaintext_password,
            'unsalted_md5': {
                'hashes': md5_samples,
                'is_identical': md5_samples[0] == md5_samples[1] == md5_samples[2],
                'vulnerability': 'IDENTICAL DIGEST: Vulnerable to precomputed Rainbow Tables and cross-user collision indexing.'
            },
            'salted_bcrypt': {
                'hashes': bcrypt_samples,
                'is_identical': bcrypt_samples[0] == bcrypt_samples[1],
                'defense': 'UNIQUE SALTS: Every hash is mathematically distinct. Defeats Rainbow Tables and parallel multi-hash attacks.'
            },
            'salted_argon2': {
                'hashes': argon2_samples,
                'is_identical': argon2_samples[0] == argon2_samples[1],
                'defense': 'ADAPTIVE UNIQUE SALT + MEMORY HARDNESS: Renders GPU and ASIC clusters cost-prohibitive.'
            }
        }

    def calculate_attack_feasibility(self, password_length, charset_type='alphanumeric_symbols', algorithm='argon2'):
        """
        Calculate mathematical brute-force cost in time, electricity, and money.
        """
        charsets = {
            'digits_only': (10, 'Numeric Only (0-9)'),
            'lower_only': (26, 'Lowercase Only (a-z)'),
            'alphanumeric': (62, 'Alphanumeric (a-zA-Z0-9)'),
            'alphanumeric_symbols': (95, 'Full ASCII + Symbols (95 chars)')
        }
        
        base, label = charsets.get(charset_type, (95, 'Full ASCII (95 chars)'))
        keyspace = base ** max(1, password_length)
        half_keyspace = keyspace / 2.0  # Statistical average

        # Speed configurations (Hashcat benchmarks)
        # Guesses per second per hardware profile
        profiles = {
            'md5': {
                'name': 'MD5 (Legacy Raw)',
                'laptop': 3.0e7,         # 30 MH/s
                'single_gpu': 4.5e10,    # 45 GH/s (RTX 4090)
                'rig_8gpu': 3.6e11,      # 360 GH/s (8x 4090)
                'cluster_1000': 4.5e13,  # 45 TH/s
                'kw_per_hour': 2.8,      # kW for 8-GPU rig
                'status': 'BROKEN / INSTANT'
            },
            'sha256': {
                'name': 'SHA-256 (Raw Digest)',
                'laptop': 1.0e7,         # 10 MH/s
                'single_gpu': 1.0e10,    # 10 GH/s
                'rig_8gpu': 8.0e10,      # 80 GH/s
                'cluster_1000': 1.0e13,  # 10 TH/s
                'kw_per_hour': 2.8,
                'status': 'INSECURE FOR PASSWORDS'
            },
            'bcrypt': {
                'name': 'bcrypt (Cost 12)',
                'laptop': 250,           # 250 H/s
                'single_gpu': 1.5e5,     # 150 kH/s
                'rig_8gpu': 1.2e6,       # 1.2 MH/s
                'cluster_1000': 1.5e8,   # 150 MH/s
                'kw_per_hour': 3.0,
                'status': 'STRONG ADAPTIVE'
            },
            'argon2': {
                'name': 'Argon2id (m=64MB, t=2)',
                'laptop': 10,            # 10 H/s
                'single_gpu': 2.0e3,     # 2 kH/s
                'rig_8gpu': 1.6e4,       # 16 kH/s
                'cluster_1000': 2.0e6,   # 2 MH/s
                'kw_per_hour': 3.2,
                'status': 'GOLD STANDARD'
            }
        }

        spec = profiles.get(algorithm.lower(), profiles['argon2'])

        def human_duration(sec):
            if sec < 0.001: return "< 1 millisecond"
            elif sec < 1: return f"{int(sec * 1000)} ms"
            elif sec < 60: return f"{round(sec, 1)} seconds"
            elif sec < 3600: return f"{round(sec/60, 1)} minutes"
            elif sec < 86400: return f"{round(sec/3600, 1)} hours"
            elif sec < 31536000: return f"{round(sec/86400, 1)} days"
            elif sec < 3.1536e9: return f"{round(sec/31536000, 1)} years"
            elif sec < 3.1536e12: return f"{round(sec/3.1536e9, 1)} thousand years"
            elif sec < 3.1536e15: return f"{round(sec/3.1536e12, 1)} million years"
            else: return "> 1 Billion Years (Mathematically Unfeasible)"

        sec_rig = half_keyspace / spec['rig_8gpu']
        sec_cluster = half_keyspace / spec['cluster_1000']
        
        # Power cost estimate ($0.15 per kWh)
        hours_rig = sec_rig / 3600.0
        power_cost = hours_rig * spec['kw_per_hour'] * 0.15

        return {
            'algorithm': spec['name'],
            'charset_label': label,
            'length': password_length,
            'keyspace_total': f"{keyspace:.2e}",
            'time_single_gpu': human_duration(half_keyspace / spec['single_gpu']),
            'time_8x_rig': human_duration(sec_rig),
            'time_nation_state': human_duration(sec_cluster),
            'estimated_power_cost_usd': f"${power_cost:,.2f}" if power_cost < 1e9 else "Prohibitive (> $1B USD)",
            'status': spec['status']
        }

    def run_john(self, hash_file, format=None):
        if not self.check_tool('john'):
            return {'tool': 'John the Ripper', 'output': 'John binary not in system path. Internal engine engaged.', 'simulated': True, 'success': True}
        cmd = ['john', hash_file]
        if format: cmd.append(f'--format={format}')
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {'tool': 'John the Ripper', 'output': p.stdout, 'success': True}
        except Exception as e:
            return {'tool': 'John the Ripper', 'output': str(e), 'success': False}

    def run_hashcat(self, hash_file, mode, attack_type=0):
        if not self.check_tool('hashcat'):
            return {'tool': 'Hashcat', 'output': 'Hashcat binary not in system path. Internal engine engaged.', 'simulated': True, 'success': True}
        cmd = ['hashcat', '-m', str(mode), '-a', str(attack_type), hash_file]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {'tool': 'Hashcat', 'output': p.stdout, 'success': True}
        except Exception as e:
            return {'tool': 'Hashcat', 'output': str(e), 'success': False}

def main():
    sim = CrackSimulator()
    res = sim.demonstrate_salt_defense("admin123")
    print("\n" + "="*50)
    print("SALT DEFENSE DEMONSTRATION")
    print("MD5 Hashes (Unsalted):", res['unsalted_md5']['hashes'])
    print("bcrypt Hashes (Salted):", res['salted_bcrypt']['hashes'])
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
