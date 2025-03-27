import firebase_admin
from firebase_admin import credentials, firestore, auth

cred = credentials.Certificate("sleepwell-7ec3a-firebase-adminsdk-fbsvc-0d4dfada6e.json")
firebase_admin.initialize_app(cred)

db = firestore.client()

print("Firebase is connected!")
