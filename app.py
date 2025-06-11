from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import pytesseract
from PIL import Image
import requests
from io import BytesIO
import re
import tldextract

app = Flask(__name__)

# If using Windows locally, uncomment and set the path below:
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def analyze_text(text):
    verdict = "SAFE ✅"
    report = ""
    phishing_keywords = ['verify your account', 'suspended', 'click here', 'login', 'update your payment', 'reset password']

    for keyword in phishing_keywords:
        if keyword.lower() in text.lower():
            verdict = "DANGEROUS 🚨"
            report += f"Found keyword: '{keyword}'\n"

    urls = re.findall(r'https?://\S+', text)
    for url in urls:
        ext = tldextract.extract(url)
        if ext.domain not in ['google', 'whatsapp', 'amazon', 'microsoft']:  # Safe domains
            verdict = "DANGEROUS 🚨"
            report += f"Suspicious URL: {url}\n"

    if not report:
        report = "No suspicious keywords or URLs found."

    return verdict, report

def extract_text_from_image(img_url):
    try:
        img_response = requests.get(img_url)
        image = Image.open(BytesIO(img_response.content))
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception as e:
        return f"[OCR Error] {str(e)}"

@app.route("/bot", methods=["POST"])
def bot():
    incoming_msg = request.values.get('Body', '')
    num_media = int(request.values.get('NumMedia', 0))
    resp = MessagingResponse()
    msg = resp.message()

    if num_media > 0:
        img_url = request.values.get("MediaUrl0")
        extracted_text = extract_text_from_image(img_url)
        verdict, report = analyze_text(extracted_text)
        msg.body(f"🖼️ Text extracted from image:\n{extracted_text[:300]}...\n\nPhishShield Verdict:\n{verdict}\n{report}")
    else:
        verdict, report = analyze_text(incoming_msg)
        msg.body(f"PhishShield Report:\nVerdict: {verdict}\n{report}")

    return str(resp)
