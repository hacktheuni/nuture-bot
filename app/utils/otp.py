import string, random
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import hashlib

from app.core.config import settings

def generate_otp():
    otp = ''.join(random.choices(string.digits, k=6))
    return otp

def hash_otp(otp: str):
    return hashlib.sha256(otp.encode()).hexdigest()
    
def send_email_otp(to_email: str, otp_code: str):
    message = Mail(
        from_email=settings.SENDGRID_FROM_EMAIL,
        to_emails=to_email,
        subject="Your OTP Code",
        html_content=f"""
        <h3>Welcome to NutureBot</h3>
        <p>Your OTP code is: <b>{otp_code}</b></p>
        <p>This code will expire in 5 minutes.</p>
        """
    )
    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"OTP email sent to {to_email}, Status: {response.status_code}")
    except Exception as e:
        print(f"Failed to send OTP email: {str(e)}")

