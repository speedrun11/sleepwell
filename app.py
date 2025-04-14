from flask import Flask, request, jsonify, render_template, redirect, url_for
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import firebase_admin
from firebase_admin import credentials, auth
import os

app = Flask(__name__)

if not firebase_admin._apps:
    cred_path = os.path.join(os.path.dirname(__file__), 'sleepwell-7ec3a-firebase-adminsdk-fbsvc-0d2a905bbb.json')
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('session')
        if not token:
            return redirect(url_for('home'))
        try:
            decoded_claims = auth.verify_session_cookie(token)
            return f(*args, **kwargs)
        except:
            return redirect(url_for('home'))
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('session')
        if not token:
            return redirect(url_for('home'))
        try:
            decoded_claims = auth.verify_session_cookie(token)
            # Verify admin status through claims
            if not decoded_claims.get('admin'):
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"Admin verification failed: {str(e)}")
            return redirect(url_for('dashboard'))
    return decorated_function

def handle_errors(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"Error in {f.__name__}: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500
    return wrapper

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard.html")
@auth_required
def dashboard():
    try:
        session_cookie = request.cookies.get('session')
        if not session_cookie:
            return redirect(url_for('home'))
            
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user = auth.get_user(decoded_claims['uid'])
        
        return render_template("dashboard.html", user={
            'email': user.email,
            'name': user.display_name
        })
        
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return redirect(url_for('home'))

# Add this with your other routes
@app.route("/admin.html")
@admin_required  # Use the new decorator
def admin_dashboard():
    try:
        session_cookie = request.cookies.get('session')
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user = auth.get_user(decoded_claims['uid'])
        
        return render_template("admin.html", user={
            'email': user.email,
            'name': user.display_name or "Admin",
            'is_admin': True  # Explicitly pass admin status
        })
        
    except Exception as e:
        app.logger.error(f"Admin dashboard error: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/sleepanalysis')
def sleep_analysis():
    return render_template('sleepanalysis.html')

@app.route('/decisiontree')
def decision_tree():
    return render_template('decisiontree.html')

@app.route('/recommendations')
def recommendations():
    return render_template('recommendations.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route("/signup", methods=["POST"])
@limiter.limit("5 per minute")
@handle_errors
def signup():
    data = request.get_json()
    
    if not data or not all(k in data for k in ["email", "password", "first_name", "last_name"]):
        return jsonify({"error": "Missing required fields"}), 400
    
    email = data["email"].strip()
    password = data["password"]
    first_name = data["first_name"].strip()
    last_name = data["last_name"].strip()

    if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
        return jsonify({"error": "Invalid email format"}), 400
    
    if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
        return jsonify({
            "error": "Password must be at least 8 characters with at least one uppercase letter and one number"
        }), 400

    try:
        user = auth.create_user(
            email=email,
            password=password,
            display_name=f"{first_name} {last_name}"
        )
        
        id_token = data.get('idToken')
        if not id_token:
            return jsonify({"error": "Missing ID token"}), 400
            
        session_cookie = auth.create_session_cookie(
            id_token, 
            expires_in=3600
        )
        
        response = jsonify({
            "message": "User created successfully",
            "redirect": "/dashboard.html"
        })
        
        response.set_cookie(
            'session',
            session_cookie,
            httponly=True,
            secure=False, 
            samesite='Lax',
            max_age=3600
        )
        
        return response
        
    except auth.EmailAlreadyExistsError:
        return jsonify({"error": "Email already in use"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
@handle_errors
def login():
    data = request.get_json()
    
    if not data or "idToken" not in data:
        return jsonify({"error": "Missing ID token"}), 400
    
    try:
        # Verify the ID token first
        decoded_token = auth.verify_id_token(data["idToken"])
        
        # Then create session cookie
        session_cookie = auth.create_session_cookie(
            data["idToken"], 
            expires_in=3600
        )
        
        response = jsonify({
            "status": "success",
            "redirect": "/dashboard.html"
        })
        
        response.set_cookie(
            'session',
            session_cookie,
            httponly=True,
            secure=False,  # Change to True in production with HTTPS
            samesite='Lax',
            max_age=3600
        )
        
        return response
        
    except auth.InvalidIdTokenError:
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    
    try:
        # Verify the ID token
        decoded_token = auth.verify_id_token(data["idToken"])
        user = auth.get_user(decoded_token['uid'])
        
        # Check if this is an admin user (by email or existing claims)
        is_admin = decoded_token.get('admin') or user.email == "admin@sleepwell.com"
        
        if not is_admin:
            return jsonify({"error": "Admin access only"}), 403
        
        # Set custom claims if not already set
        if not decoded_token.get('admin'):
            auth.set_custom_user_claims(decoded_token['uid'], {'admin': True})
        
        # Create session cookie
        session_cookie = auth.create_session_cookie(
            data["idToken"], 
            expires_in=3600
        )
        
        response = jsonify({
            "status": "success",
            "redirect": "/admin.html",
            "is_admin": True
        })
        
        response.set_cookie(
            'session',
            session_cookie,
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=3600
        )
        
        return response
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/logout")
def logout():
    response = redirect(url_for('home'))
    response.delete_cookie('session') 
    return response

if __name__ == "__main__":
    app.run(debug=True)