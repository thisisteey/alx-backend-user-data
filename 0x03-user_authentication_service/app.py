#!/usr/bin/env python3
"""Flask application with user authentication features"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """Content of the home page"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def create_user() -> str:
    """Payload indicating account creation status"""
    email, password = request.form.get("email"), request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login() -> str:
    """Payload indicating login status"""
    email, password = request.form.get("email"), request.form.get("password")
    if not AUTH.valid_login(email, password):
        abort(401)
    newSessionID = AUTH.create_session(email)
    loginResp = jsonify({"email": email, "message": "logged in"})
    loginResp.set_cookie("session_id", newSessionID)
    return loginResp


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """Logouts a session and redirects to home route"""
    sessionCookie = request.cookies.get("session_id")
    userSession = AUTH.get_user_from_session_id(sessionCookie)
    if userSession is None:
        abort(403)
    AUTH.destroy_session(userSession.id)
    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """Gets and returns the user's profile information"""
    currSessionID = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(currSessionID)
    if user is None:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    """Payload for password reset request"""
    userEmail = request.form.get("email")
    pwdResetTok = None
    try:
        pwdResetTok = AUTH.get_reset_password_token(userEmail)
    except ValueError:
        pwdResetTok = None
    if pwdResetTok is None:
        abort(403)
    return jsonify({"email": userEmail, "reset_token": pwdResetTok})


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password() -> str:
    """Payload indicating the success or failure of password update"""
    userEmail = request.form.get("email")
    pwdResetTok = request.form.get("reset_token")
    newPwd = request.form.get("new_password")
    pwdUpdated = False
    try:
        AUTH.update_password(pwdResetTok, newPwd)
        pwdUpdated = True
    except ValueError:
        pwdUpdated = False
    if not pwdUpdated:
        abort(403)
    return jsonify({"email": userEmail, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
