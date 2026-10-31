import hashlib
import time
import os
import csv
import argparse
import yaml
import bcrypt
import argon2
from passlib.hash import scrypt
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HashGenerator:
    def __init__(self, config_path='config.yaml'):
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                'paths': {'hash_dir': 'data/generated_hashes'},
                'hashing': {
                    'algorithms': ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'scrypt', 'argon2'],
                    'default_rounds': {'bcrypt': 12, 'argon2': 2}
                }
            }
        
        self.output_dir = self.config.get('paths', {}).get('hash_dir', 'data/generated_hashes')
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_md5(self, password):
        return hashlib.md5(password.encode('utf-8')).hexdigest()

    def generate_sha1(self, password):
        return hashlib.sha1(password.encode('utf-8')).hexdigest()

    def generate_sha256(self, password):
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def generate_sha512(self, password):
        return hashlib.sha512(password.encode('utf-8')).hexdigest()

    def generate_bcrypt(self, password, rounds=None):
        if rounds is None:
            rounds = self.config.get('hashing', {}).get('default_rounds', {}).get('bcrypt', 12)
        rounds = max(4, min(16, int(rounds)))
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def generate_argon2(self, password, time_cost=None, memory_cost=65536, parallelism=1):
        if time_cost is None:
            time_cost = self.config.get('hashing', {}).get('default_rounds', {}).get('argon2', 2)
        ph = argon2.PasswordHasher(
            time_cost=int(time_cost),
            memory_cost=int(memory_cost),
            parallelism=int(parallelism),
            hash_len=32,
            type=argon2.Type.ID
        )
        return ph.hash(password)

    def generate_scrypt(self, password):
        return scrypt.hash(password)

    def generate_all_hashes(self, password, bcrypt_rounds=12, argon2_time=2):
        """Generate all supported hash representations for a single password."""
        return {
            'md5': {
                'name': 'MD5',
                'hash': self.generate_md5(password),
                'family': 'Legacy / Fast',
                'status': 'BROKEN',
                'description': '128-bit digest. Completely broken by collision attacks; GPU can test billions/sec.'
            },
            'sha1': {
                'name': 'SHA-1',
                'hash': self.generate_sha1(password),
                'family': 'Legacy / Fast',
                'status': 'DEPRECATED',
                'description': '160-bit digest. Collisions demonstrated (SHAttered); insecure for authentication.'
            },
            'sha256': {
                'name': 'SHA-256',
                'hash': self.generate_sha256(password),
                'family': 'Standard Fast Cryptographic',
                'status': 'UNSAFE FOR PASSWORDS',
                'description': 'Cryptographically secure for integrity/signatures, but far too fast for password hashing without adaptive key stretching.'
            },
            'sha512': {
                'name': 'SHA-512',
                'hash': self.generate_sha512(password),
                'family': 'Standard Fast Cryptographic',
                'status': 'UNSAFE FOR PASSWORDS',
                'description': '512-bit digest. Fast on 64-bit architectures, vulnerable to hardware-accelerated attacks.'
            },
            'bcrypt': {
                'name': f'bcrypt (Work Factor: {bcrypt_rounds})',
                'hash': self.generate_bcrypt(password, rounds=bcrypt_rounds),
                'family': 'Adaptive Memory/CPU Hard',
                'status': 'ENTERPRISE RECOMMENDED',
                'description': 'Based on Blowfish. Built-in salt, configurable work factor; highly resistant to GPUs.'
            },
            'scrypt': {
                'name': 'scrypt',
                'hash': self.generate_scrypt(password),
                'family': 'Memory-Hard KDF',
                'status': 'STRONG',
                'description': 'Explicitly engineered to require large amounts of RAM to defeat ASIC and FPGA attacks.'
            },
            'argon2': {
                'name': f'Argon2id (t={argon2_time}, m=64MB)',
                'hash': self.generate_argon2(password, time_cost=argon2_time),
                'family': 'State-of-the-Art Winner of PHC',
                'status': 'INDUSTRY GOLD STANDARD',
                'description': 'Winner of the Password Hashing Competition. Maximum resistance against side-channel and GPU/ASIC attacks.'
            }
        }

    def deconstruct_hash(self, hash_str):
        """
        Analyze and deconstruct an unknown hash string into its cryptographic components.
        """
        h = hash_str.strip()
        length = len(h)
        
        # Check Argon2
        if h.startswith('$argon2'):
            parts = h.split('$')
            # Format: $argon2id$v=19$m=65536,t=2,p=1$salt$hash
            variant = parts[1] if len(parts) > 1 else 'argon2'
            params = parts[3] if len(parts) > 3 else 'standard'
            salt = parts[4] if len(parts) > 4 else 'present'
            digest = parts[5] if len(parts) > 5 else ''
            return {
                'detected_algo': f'Argon2 ({variant})',
                'category': 'Adaptive Memory-Hard (PHC Winner)',
                'security_tier': 'GOLD_STANDARD',
                'bits': 256,
                'salt_present': True,
                'work_factor': params,
                'salt': salt[:16] + '...' if len(salt) > 16 else salt,
                'digest_sample': digest[:16] + '...' if digest else h[-16:],
                'hashcat_mode': '-m 12100 (Argon2)',
                'john_format': '--format=argon2',
                'summary': 'State-of-the-art password hash with configurable memory, time, and thread parallelism.'
            }
        
        # Check bcrypt
        if h.startswith(('$2a$', '$2b$', '$2y$', '$2x$')):
            parts = h.split('$')
            cost = parts[2] if len(parts) > 2 else '12'
            remainder = parts[3] if len(parts) > 3 else ''
            salt = remainder[:22]
            digest = remainder[22:]
            return {
                'detected_algo': f'bcrypt ({parts[1]})',
                'category': 'Adaptive CPU-Hard (Blowfish-derived)',
                'security_tier': 'RECOMMENDED',
                'bits': 184,
                'salt_present': True,
                'work_factor': f'2^{cost} ({2**int(cost):,} iterations)' if cost.isdigit() else cost,
                'salt': salt,
                'digest_sample': digest,
                'hashcat_mode': '-m 3200 (bcrypt)',
                'john_format': '--format=bcrypt',
                'summary': 'Standard enterprise password hash with built-in 128-bit salt and exponential work factor.'
            }

        # Check scrypt
        if h.startswith('$scrypt$'):
            return {
                'detected_algo': 'scrypt',
                'category': 'Memory-Hard Key Derivation Function',
                'security_tier': 'STRONG',
                'bits': 256,
                'salt_present': True,
                'work_factor': 'Configurable (N, r, p)',
                'salt': 'Embedded in prefix',
                'digest_sample': h[-20:],
                'hashcat_mode': '-m 8900 (scrypt)',
                'john_format': '--format=scrypt',
                'summary': 'Engineered to require large blocks of physical memory, neutralizing GPU clusters.'
            }

        # Check hex hashes
        is_hex = bool(re.match(r'^[0-9a-fA-F]+$', h))
        if is_hex:
            if length == 32:
                return {
                    'detected_algo': 'MD5',
                    'category': 'Fast Cryptographic Digest (Obsolete)',
                    'security_tier': 'CRITICAL_BROKEN',
                    'bits': 128,
                    'salt_present': False,
                    'work_factor': '1 iteration (No stretching)',
                    'salt': 'None (Unsalted raw digest)',
                    'digest_sample': h,
                    'hashcat_mode': '-m 0 (MD5)',
                    'john_format': '--format=raw-md5',
                    'summary': 'FATALLY VULNERABLE: Highly susceptible to rainbow tables, collisions, and GPU brute-force at billions of hashes/second.'
                }
            elif length == 40:
                return {
                    'detected_algo': 'SHA-1',
                    'category': 'Fast Cryptographic Digest (Deprecated)',
                    'security_tier': 'DEPRECATED',
                    'bits': 160,
                    'salt_present': False,
                    'work_factor': '1 iteration (No stretching)',
                    'salt': 'None (Unsalted raw digest)',
                    'digest_sample': h,
                    'hashcat_mode': '-m 100 (SHA1)',
                    'john_format': '--format=raw-sha1',
                    'summary': 'DEPRECATED: Collision attacks demonstrated in 2017 (SHAttered). Unacceptable for passwords.'
                }
            elif length == 64:
                return {
                    'detected_algo': 'SHA-256',
                    'category': 'Fast General-Purpose Hash',
                    'security_tier': 'INSECURE_FOR_PASSWORDS',
                    'bits': 256,
                    'salt_present': False,
                    'work_factor': '1 iteration (Unless PBKDF2 applied)',
                    'salt': 'None detected',
                    'digest_sample': h,
                    'hashcat_mode': '-m 1400 (SHA256)',
                    'john_format': '--format=raw-sha256',
                    'summary': 'INSUFFICIENT FOR AUTHENTICATION: SHA-256 is mathematically secure for data integrity, but dangerous for passwords without salt and key stretching.'
                }
            elif length == 128:
                return {
                    'detected_algo': 'SHA-512',
                    'category': 'Fast General-Purpose Hash',
                    'security_tier': 'INSECURE_FOR_PASSWORDS',
                    'bits': 512,
                    'salt_present': False,
                    'work_factor': '1 iteration',
                    'salt': 'None detected',
                    'digest_sample': h[:20] + '...',
                    'summary': 'Fast general-purpose 512-bit digest. High speed enables GPU cluster cracking.'
                }

        return {
            'detected_algo': 'Unknown Format',
            'category': 'Unidentified Ciphertext',
            'security_tier': 'UNKNOWN',
            'bits': length * 4 if is_hex else length * 8,
            'salt_present': '$' in h,
            'work_factor': 'Undetermined',
            'salt': 'N/A',
            'digest_sample': h[:20] + ('...' if length > 20 else ''),
            'summary': 'Could not unambiguously classify hash format. Verify input string.'
        }

    def benchmark_suite(self, test_passwords=None, algorithms=None, bcrypt_rounds=12, argon2_time=2):
        """
        Execute an accurate real-time benchmark across selected algorithms.
        """
        if test_passwords is None:
            test_passwords = ["SecurityTest#2026", "Enterprise_Vault_Key!"]
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256', 'bcrypt', 'argon2']

        results = []
        for algo in algorithms:
            t0 = time.perf_counter()
            hashes = []
            for p in test_passwords:
                if algo == 'md5':
                    h = self.generate_md5(p)
                elif algo == 'sha1':
                    h = self.generate_sha1(p)
                elif algo == 'sha256':
                    h = self.generate_sha256(p)
                elif algo == 'sha512':
                    h = self.generate_sha512(p)
                elif algo == 'bcrypt':
                    h = self.generate_bcrypt(p, rounds=bcrypt_rounds)
                elif algo == 'argon2':
                    h = self.generate_argon2(p, time_cost=argon2_time)
                elif algo == 'scrypt':
                    h = self.generate_scrypt(p)
                else:
                    continue
                hashes.append(h)
            
            elapsed = time.perf_counter() - t0
            avg_time = elapsed / len(test_passwords) if test_passwords else 0
            hash_len = len(hashes[0]) if hashes else 0
            
            # Security ratings
            if algo in ['md5', 'sha1']:
                tier = 'Legacy / Broken'
                risk = 'High'
                color = '#EF4444'
            elif algo in ['sha256', 'sha512']:
                tier = 'Fast (Non-Adaptive)'
                risk = 'Medium'
                color = '#F59E0B'
            elif algo == 'bcrypt':
                tier = 'Adaptive CPU-Hard'
                risk = 'Low'
                color = '#3B82F6'
            elif algo == 'argon2':
                tier = 'Memory-Hard (PHC Winner)'
                risk = 'Minimal'
                color = '#10B981'
            else:
                tier = 'Standard KDF'
                risk = 'Low'
                color = '#6366F1'

            results.append({
                'algorithm': algo.upper(),
                'avg_time': avg_time,
                'avg_time_ms': avg_time * 1000.0,
                'hashes_per_sec': (1.0 / avg_time) if avg_time > 0 else 0,
                'hash_length': hash_len,
                'sample_hash': hashes[0] if hashes else '',
                'tier': tier,
                'risk': risk,
                'color': color
            })
        return results

    def process_file(self, input_file):
        """Process passwords from a file and save hashes."""
        logger.info(f"Processing passwords from {input_file}")
        if not os.path.exists(input_file):
            logger.error(f"Input file {input_file} not found.")
            return []

        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]

        stats = []
        for algo in ['md5', 'sha256', 'bcrypt', 'argon2']:
            start_time = time.time()
            hashes = []
            for pwd in passwords:
                if algo == 'md5': h = self.generate_md5(pwd)
                elif algo == 'sha256': h = self.generate_sha256(pwd)
                elif algo == 'bcrypt': h = self.generate_bcrypt(pwd)
                elif algo == 'argon2': h = self.generate_argon2(pwd)
                hashes.append((pwd, h))
            
            duration = time.time() - start_time
            stats.append({
                'algorithm': algo,
                'count': len(passwords),
                'total_time': duration,
                'avg_time': duration / len(passwords) if passwords else 0,
                'hash_length': len(hashes[0][1]) if hashes else 0
            })

            output_path = os.path.join(self.output_dir, f"{algo}_hashes.txt")
            with open(output_path, 'w', encoding='utf-8') as f:
                for pwd, h in hashes:
                    f.write(f"{h}\n")

        return stats

def main():
    generator = HashGenerator()
    bench = generator.benchmark_suite()
    print("\n" + "="*70)
    print(f"{'Algorithm':<12} | {'Avg Time (ms)':<15} | {'Rate (H/s)':<15} | {'Security Tier':<20}")
    print("-" * 70)
    for b in bench:
        print(f"{b['algorithm']:<12} | {b['avg_time_ms']:<15.3f} | {b['hashes_per_sec']:<15.1f} | {b['tier']:<20}")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
