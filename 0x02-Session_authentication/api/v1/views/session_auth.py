#!/usr/bin/env python3
"""Module for handling user login and session mgt in session auth views"""
from api.v1.views import app_views
from typing import Tuple
from flask import request, jsonify, abort
from models.user import User
import os


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login() -> Tuple[str, int]:
    """Handle user login via POST request to /api/v1/auth_session/login"""
    userNFres = {"error": "no user found for this email"}
    email = request.form.get("email")
    if email is None or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get("password")
    if password is None or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400
    try:
        usersList = User.search({"email": email})
    except Exception:
        return jsonify(userNFres), 404
    if len(usersList) <= 0:
        return jsonify(userNFres), 404
    if usersList[0].is_valid_password(password):
        from api.v1.app import auth
        sessionToken = auth.create_session(getattr(usersList[0], "id"))
        loginRes = jsonify(usersList[0].to_json())
        loginRes.set_cookie(os.getenv("SESSION_NAME"), sessionToken)
        return loginRes
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
        "/auth_session/logout", methods=["DELETE"], strict_slashes=False)
def logout() -> Tuple[str, int]:
    """Handles user logout via DELETE request to /api/v1/auth_session/logout"""
    from api.v1.app import auth
    sessTerminated = auth.destroy_session(request)
    if not sessTerminated:
        abort(404)
    return jsonify({})
