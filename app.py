from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
from analyzer import is_phishing_text

app = Flask(__name__)

@app.route("/bot", methods=["POST"])
def bot():
    msg = request.form.get("Body")
    resp = MessagingResponse()

    if msg:
        level, explanation = is_phishing_text(msg)
        reply = f"PhishShield Report:\n\nVerdict: *{level}*\n\n"
        reply += "\n".join(explanation)
    else:
        reply = "Please send a message or a screenshot."

    resp.message(reply)
    return str(resp)

if __name__ == "__main__":
    app.run()
