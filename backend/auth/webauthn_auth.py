"""
WebAuthn — Authentification biométrique
Empreinte digitale / Face ID / Windows Hello
CHOC JURY: login sans mot de passe via biométrie
"""
import webauthn
import json
import base64
from database.mongo_client import get_cloud_db

RP_ID = "your-app.netlify.app"
RP_NAME = "BlockchainAuth FSAC"
ORIGIN = "https://your-app.netlify.app"

def generate_registration_options(username, user_id):
    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id.encode(),
        user_name=username,
        user_display_name=username,
        attestation=webauthn.AttestationConveyancePreference.NONE,
        authenticator_selection=webauthn.AuthenticatorSelectionCriteria(
            authenticator_attachment=webauthn.AuthenticatorAttachment.PLATFORM,
            user_verification=webauthn.UserVerificationRequirement.REQUIRED,
            resident_key=webauthn.ResidentKeyRequirement.PREFERRED,
        ),
    )
    return options

def verify_registration_response(username, credential, challenge):
    verified = webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
    )
    db = get_cloud_db()
    db.users.update_one(
        {"username": username},
        {"$set": {
            "webauthn_credential_id": base64.b64encode(verified.credential_id).decode(),
            "webauthn_public_key": base64.b64encode(verified.credential_public_key).decode(),
            "sign_count": verified.sign_count,
            "webauthn_enabled": True
        }}
    )
    return True

def generate_authentication_options(username):
    db = get_cloud_db()
    user = db.users.find_one({"username": username})
    if not user or not user.get("webauthn_enabled"):
        return None
    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            webauthn.PublicKeyCredentialDescriptor(
                id=base64.b64decode(user["webauthn_credential_id"])
            )
        ],
        user_verification=webauthn.UserVerificationRequirement.REQUIRED,
    )
    return options

def verify_authentication_response(username, credential, challenge):
    db = get_cloud_db()
    user = db.users.find_one({"username": username})
    verified = webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        credential_public_key=base64.b64decode(user["webauthn_public_key"]),
        credential_current_sign_count=user.get("sign_count", 0),
    )
    db.users.update_one(
        {"username": username},
        {"$set": {"sign_count": verified.new_sign_count}}
    )
    return True