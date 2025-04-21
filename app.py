from flask import Flask, request, jsonify, render_template, redirect, url_for
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import firebase_admin
from firebase_admin import credentials, auth
import os
from firebase_admin import firestore

app = Flask(__name__)

if not firebase_admin._apps:
    cred_path = os.path.join(os.path.dirname(__file__), 'sleepwell-7ec3a-firebase-adminsdk-fbsvc-0d2a905bbb.json')
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)
    db = firestore.client()

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
            app.logger.warning("No session token in auth_required")
            return redirect(url_for('home'))
        try:
            decoded_claims = auth.verify_session_cookie(token, check_revoked=True)
            app.logger.info(f"Authenticated user: {decoded_claims['uid']}")
            return f(*args, **kwargs)
        except auth.InvalidSessionCookieError:
            app.logger.warning("Invalid session cookie")
            return redirect(url_for('home'))
        except auth.RevokedSessionCookieError:
            app.logger.warning("Revoked session cookie")
            return redirect(url_for('home'))
        except Exception as e:
            app.logger.error(f"Auth error: {str(e)}")
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

@app.route("/check-cookie")
def check_cookie():
    return jsonify({
        'cookie_present': bool(request.cookies.get('session')),
        'headers': dict(request.headers)
    })

@app.route("/time-check")
def time_check():
    import time
    return {
        "server_time": time.time(),
        "server_clock": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "message": "Compare with https://time.is"
    }

@app.route('/api/save-sleep-entry', methods=['POST'])
@auth_required
def save_sleep_entry():
    try:
        session_cookie = request.cookies.get('session')
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user_id = decoded_claims['uid']
        
        user_ref = db.collection('users').document(user_id)
        user_ref.update({
            'entriesCount': firestore.Increment(1),
            'updatedAt': firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({
            "success": True,
            "message": "User entries count updated successfully"
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error updating user entries count: {str(e)}")
        return jsonify({
            "error": f"Failed to update entries count: {str(e)}"
        }), 500

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/user/dashboard.html")
def dashboard():
    try:
        session_cookie = request.cookies.get('session')
        if not session_cookie:
            return redirect(url_for('home'))
            
        decoded_claims = auth.verify_session_cookie(
            session_cookie,
            clock_skew_seconds=60,
            check_revoked=False
        )
        user = auth.get_user(decoded_claims['uid'])
        return render_template("/user/dashboard.html")
        
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        return redirect(url_for('home'))

@app.route("/admin/admindashboard.html")
@admin_required
def admin_dashboard():
    try:
        session_cookie = request.cookies.get('session')
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user = auth.get_user(decoded_claims['uid'])
        
        return render_template("admin/admindashboard.html", user={
            'email': user.email,
            'name': user.display_name or "Admin",
            'is_admin': True
        })
        
    except Exception as e:
        app.logger.error(f"Admin dashboard error: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route("/admin/usermanagement.html")
@admin_required
def user_management():
    try:
        session_cookie = request.cookies.get('session')
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user = auth.get_user(decoded_claims['uid'])
        
        return render_template("admin/usermanagement.html", user={
            'email': user.email,
            'name': user.display_name or "Admin",
            'is_admin': True
        })
        
    except Exception as e:
        app.logger.error(f"User management error: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route('/api/createUser', methods=['POST'])
@admin_required
def create_user():
    try:
        data = request.get_json()
        
        user = auth.create_user(
            email=data['email'],
            password=data['password']
        )
        
        db.collection('users').document(user.uid).set({
            'userId': user.uid,
            'firstName': data['firstName'],
            'lastName': data['lastName'],
            'displayName': f"{data['firstName']} {data['lastName']}",
            'email': data['email'],
            'isAdmin': data.get('isAdmin', False),
            'isActive': True,
            'createdAt': firestore.SERVER_TIMESTAMP,
            'lastLogin': firestore.SERVER_TIMESTAMP,
            'entriesCount': 0,
            'updatedAt': firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/users/<user_id>', methods=['DELETE'])
@admin_required
@handle_errors
def delete_user(user_id):
    try:
        try:
            auth.get_user(user_id)
        except auth.UserNotFoundError:
            return jsonify({"error": "User not found in authentication system"}), 404

        entries_ref = db.collection('sleepEntries').where('userId', '==', user_id)
        entries = entries_ref.stream()
        
        batch = db.batch()
        batch_count = 0
        max_batch_size = 400
        
        for entry in entries:
            if batch_count >= max_batch_size:
                batch.commit()
                batch = db.batch()
                batch_count = 0
            batch.delete(entry.reference)
            batch_count += 1
        
        if batch_count > 0:
            batch.commit()

        user_ref = db.collection('users').document(user_id)
        user_ref.delete()

        auth.delete_user(user_id)

        return jsonify({
            "success": True,
            "message": f"User {user_id} and all associated data deleted successfully"
        }), 200

    except Exception as e:
        app.logger.error(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({
            "error": f"Failed to delete user: {str(e)}"
        }), 500


@app.route('/api/users/<user_id>/sleep-entries', methods=['DELETE'])
@admin_required
@handle_errors
def delete_user_sleep_entries(user_id):
    try:
        auth.get_user(user_id)
        
        entries_ref = db.collection('sleepEntries').where('userId', '==', user_id)
        entries = entries_ref.stream()
        
        batch = db.batch()
        batch_count = 0
        max_batch_size = 400
        
        for entry in entries:
            if batch_count >= max_batch_size:
                batch.commit()
                batch = db.batch()
                batch_count = 0
            batch.delete(entry.reference)
            batch_count += 1
        
        if batch_count > 0:
            batch.commit()

        db.collection('users').document(user_id).update({
            'entriesCount': 0,
            'updatedAt': firestore.SERVER_TIMESTAMP
        })

        return jsonify({
            "success": True,
            "message": f"All sleep entries for user {user_id} deleted successfully"
        }), 200

    except auth.UserNotFoundError:
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        app.logger.error(f"Error deleting sleep entries for {user_id}: {str(e)}")
        return jsonify({
            "error": f"Failed to delete sleep entries: {str(e)}"
        }), 500

@app.route("/admin/analytics.html")
@admin_required
def analytics():
    try:
        session_cookie = request.cookies.get('session')
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user = auth.get_user(decoded_claims['uid'])
        
        return render_template("admin/analytics.html", user={
            'email': user.email,
            'name': user.display_name or "Admin",
            'is_admin': True
        })
        
    except Exception as e:
        app.logger.error(f"Analytics page error: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route("/admin/feedbackmanage.html")
@admin_required
def feedback_management():
    try:
        session_cookie = request.cookies.get('session')
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user = auth.get_user(decoded_claims['uid'])
        
        return render_template("admin/feedbackmanage.html", user={
            'email': user.email,
            'name': user.display_name or "Admin",
            'is_admin': True
        })
        
    except Exception as e:
        app.logger.error(f"Feedback management error: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route("/admin/systemsettings.html")
@admin_required
def system_settings():
    try:
        session_cookie = request.cookies.get('session')
        decoded_claims = auth.verify_session_cookie(session_cookie)
        user = auth.get_user(decoded_claims['uid'])
        
        return render_template("admin/systemsettings.html", user={
            'email': user.email,
            'name': user.display_name or "Admin",
            'is_admin': True
        })
        
    except Exception as e:
        app.logger.error(f"System settings error: {str(e)}")
        return redirect(url_for('admin_dashboard'))


@app.route('/user/sleepanalysis')
def sleep_analysis():
    return render_template('/user/sleepanalysis.html')

@app.route('/user/decisiontree')
def decision_tree():
    return render_template('/user/decisiontree.html')

@app.route('/user/recommendations')
def recommendations():
    return render_template('/user/recommendations.html')

@app.route('/user/feedback')
def feedback():
    return render_template('/user/feedback.html')

@app.route('/user/settings')
def settings():
    return render_template('/user/settings.html')

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
            "redirect": "/user/dashboard.html"
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
        import time
        time.sleep(1)
        
        decoded_token = auth.verify_id_token(
            data["idToken"],
            clock_skew_seconds=60
        )
        
        session_cookie = auth.create_session_cookie(
            data["idToken"], 
            expires_in=3600
        )
        
        response = jsonify({
            "status": "success",
            "redirect": "/user/dashboard.html"
        })
        
        response.set_cookie(
            'session',
            session_cookie,
            httponly=True,
            secure=False,
            samesite='Lax',
            max_age=86400,
            path='/'
        )
        
        return response
        
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    
    try:
        decoded_token = auth.verify_id_token(data["idToken"], clock_skew_seconds=10)
        user = auth.get_user(decoded_token['uid'])
        
        is_admin = decoded_token.get('admin') or user.email == "admin@sleepwell.com"
        
        if not is_admin:
            return jsonify({"error": "Admin access only"}), 403
        
        if not decoded_token.get('admin'):
            auth.set_custom_user_claims(decoded_token['uid'], {'admin': True})
        
        session_cookie = auth.create_session_cookie(
            data["idToken"], 
            expires_in=3600
        )
        
        response = jsonify({
            "status": "success",
            "redirect": "/admin/admindashboard.html",
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