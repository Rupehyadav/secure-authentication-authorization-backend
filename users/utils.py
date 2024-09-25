from django.core.signing import Signer, TimestampSigner, BadSignature, SignatureExpired

signer = TimestampSigner()

def generate_verification_token(email):
    return signer.sign(email)

def verify_token(token, max_age=86400):  # Tokens are valid for 1 day (86400 seconds)
    try:
        email = signer.unsign(token, max_age=max_age)
        return email
    except (BadSignature, SignatureExpired):
        return None
