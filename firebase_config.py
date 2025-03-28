import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("sleepwell-7ec3a-firebase-adminsdk-fbsvc-a3ab147fc6.json")
firebase_admin.initialize_app(cred)

def create_user(email, password, first_name, last_name):
    try:
        user = auth.create_user(
            email=email,
            password=password,
            display_name=f"{first_name} {last_name}"
        )
        return user.uid
    except Exception as e:
        return str(e)

def verify_id_token(id_token):
    """Verify the ID token sent from the frontend."""
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        return str(e)
