import pyotp, qrcode, io, base64
from database.mongo_client import get_cloud_db

def generate_otp_secret():
    return pyotp.random_base32()

def generate_qr_code(username, secret):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=username, issuer_name="BlockchainAuth-FSAC"
    )
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8'), uri

def verify_otp(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)

def get_otp_secret(username):
    db = get_cloud_db()
    user = db.users.find_one({"username": username})
    return user.get("otp_secret") if user else None