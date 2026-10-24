"""Harmless fixture demonstrating static security audit scanning and secret redaction."""

import os
import subprocess
import sys

# Anti-debug check
if sys.gettrace():
    sys.exit(1)

# Secret credentials (must be redacted in audit report)
webhook_url = "https://discord.com/api/webhooks/987654321/AbCdEfGhIjKlMnOpQrStUvWxYz_12345"
telegram_api = "https://api.telegram.org/bot987654321:AAEkln_8b7X9aBcDeFgHiJkLmNoPqRsTuVw/sendMessage"
api_token = "sk-abcdef1234567890abcdef1234567890"
db_password = "password = 'SuperSecretDbPassword!'"

# File operations
with open("harvested_data.txt", "w") as f:
    f.write("test")

# Subprocess call
subprocess.run(["cmd.exe", "/c", "ipconfig /all"])

# Card verification routine indicator
def check_card_validity(cc_number, cvv, exp_month, exp_year):
    # Luhn algorithm placeholder
    return True
