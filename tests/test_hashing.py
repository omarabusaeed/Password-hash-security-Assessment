import pytest
import sys
import os

# Add modules to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.hash_generator import HashGenerator
from modules.strength_analyzer import StrengthAnalyzer

def test_md5_generation():
    gen = HashGenerator(config_path='config.yaml')
    pwd = "password123"
    result = gen.generate_md5(pwd)
    assert len(result) == 32
    # Verify MD5 of password123 is 482c811da5d5b4bc6d497ffa98491e38
    assert result == "482c811da5d5b4bc6d497ffa98491e38"

def test_entropy_calculation():
    analyzer = StrengthAnalyzer()
    # Simple password
    low = analyzer.calculate_entropy("123")
    # Complex password
    high = analyzer.calculate_entropy("S3cur3!P@ssw0rd")
    assert high > low

def test_alternative_suggestion():
    analyzer = StrengthAnalyzer()
    pwd = "test"
    alt = analyzer.suggest_alternative(pwd)
    assert len(alt) > len(pwd)
    assert any(c in "!@#$%" for c in alt)
