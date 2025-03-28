from flask import Flask, request, jsonify, render_template
import firebase_config

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    first_name = data.get("first_name")
    last_name = data.get("last_name")

    user_id = firebase_config.create_user(email, password, first_name, last_name)

    if "already exists" in user_id:
        return jsonify({"error": "Email already in use"}), 400

    return jsonify({"message": "User created successfully", "uid": user_id})

if __name__ == "__main__":
    app.run(debug=True)
