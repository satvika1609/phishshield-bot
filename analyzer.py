import re
import tldextract

phishing_keywords = [
    "urgent", "verify your account", "login now", "reset password",
    "click here", "update payment", "security alert", "limited time"
]

def is_phishing_text(text):
    score = 0
    explanation = []

    # Keyword detection
    for word in phishing_keywords:
        if word.lower() in text.lower():
            score += 1
            explanation.append(f"Found keyword: '{word}'")

    # URL pattern detection
    urls = re.findall(r'(https?://[^\s]+)', text)
    for url in urls:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        if any(x in domain for x in ["login", "secure", "verify", "account"]):
            score += 2
            explanation.append(f"Suspicious URL: {url}")

    # Scoring
    if score >= 3:
        level = "DANGEROUS 🚨"
    elif score == 2:
        level = "SUSPICIOUS ⚠️"
    else:
        level = "SAFE ✅"

    return level, explanation
