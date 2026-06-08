import os
import sys
from twilio.rest import Client
sys.path.append(os.path.abspath("server"))
import alarm_config as cfg
print("Testing Twilio client initialization...")
print(f"SID: {cfg.TWILIO_ACCOUNT_SID}")
print(f"Token: {cfg.TWILIO_AUTH_TOKEN}")
print(f"From: {cfg.TWILIO_FROM_NUMBER}")
try:
    client = Client(cfg.TWILIO_ACCOUNT_SID, cfg.TWILIO_AUTH_TOKEN)
    print("Client initialized successfully.")
    print("Attempting to send test SMS...")
    msg = client.messages.create(
        body="SafeVision Test SMS",
        from_=cfg.TWILIO_FROM_NUMBER,
        to="+972559985676"
    )
    print(f"SMS Sent successfully! SID: {msg.sid}")
except Exception as e:
    print(f"SMS Sending failed with error: {e}")
