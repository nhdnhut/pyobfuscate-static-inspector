"""Tests for static security audit scanner and secret redactor."""

from pyobfuscate_inspector.audit.redactor import SecretRedactor
from pyobfuscate_inspector.audit.scanner import SecurityScanner
from pyobfuscate_inspector.models import Severity


def test_secret_redactor():
    # OpenAI sk- token
    raw = "Authorization: Bearer sk-1234567890abcdef1234567890abcdef"
    redacted, was_red = SecretRedactor.redact(raw)
    assert was_red is True
    assert "sk-[REDACTED_API_KEY]" in redacted

    # Generic api_key assignment
    raw_assign = "api_key = 'super_secret_value'"
    redacted_assign, was_red_assign = SecretRedactor.redact(raw_assign)
    assert was_red_assign is True
    assert "***REDACTED***" in redacted_assign

    # Discord webhook
    wh = "https://discord.com/api/webhooks/123456789/AbCdEfGhIjKlMnOpQrStUvWxYz"
    redacted, was_red = SecretRedactor.redact(wh)
    assert was_red is True
    assert "[REDACTED_WEBHOOK_TOKEN]" in redacted

    # Telegram bot token
    tg = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ_1234567"
    redacted, was_red = SecretRedactor.redact(tg)
    assert was_red is True
    assert "[REDACTED_TELEGRAM_TOKEN]" in redacted

    # Password assignment
    pwd = "password = 'super_secret_password_123'"
    redacted, was_red = SecretRedactor.redact(pwd)
    assert was_red is True
    assert "***REDACTED***" in redacted


def test_security_scanner_imports_and_subprocess():
    code = """
import socket
import subprocess
import ctypes

subprocess.run(["cmd.exe", "/c", "whoami"])
"""
    scanner = SecurityScanner()
    findings = scanner.scan(code)
    categories = [f.category for f in findings]
    items = [f.item for f in findings]

    assert "import" in categories
    assert "subprocess" in categories
    assert any("subprocess.run" in it for it in items)


def test_security_scanner_file_ops_and_endpoints():
    code = """
import os
import shutil

f = open('output.txt', 'w')
f.write('test')
f.close()

os.remove('temp.dat')
shutil.rmtree('/tmp/target')

url = 'https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrSTUvwxYZ_1234567/sendMessage'
ip = '198.51.100.45'
"""
    scanner = SecurityScanner()
    findings = scanner.scan(code)
    categories = [f.category for f in findings]

    assert "file_op" in categories
    assert "exfiltration" in categories or "endpoint" in categories
    assert any("shutil.rmtree" in f.evidence for f in findings)


def test_card_checker_indicator_detection():
    code = """
# Card verification helper
def verify_card(cc_number, cvv, exp_month, exp_year):
    # Luhn check
    pass
"""
    scanner = SecurityScanner()
    findings = scanner.scan(code)
    categories = [f.category for f in findings]
    assert "card_check" in categories
