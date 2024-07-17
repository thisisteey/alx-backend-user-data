#!/usr/bin/env python3
"""Module for end-to-end integration test for `app.py`"""
import requests


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """Tests user registration functionality"""
    endpoint = f"{BASE_URL}/users"
    payload = {"email": email, "password": password}
    resp = requests.post(endpoint, data=payload)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "user created"}
    resp = requests.post(endpoint, data=payload)
    assert resp.status_code == 400
    assert resp.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Tests logging in with an incorrect password"""
    endpoint = f"{BASE_URL}/sessions"
    payload = {"email": email, "password": password}
    resp = requests.post(endpoint, data=payload)
    assert resp.status_code == 401


def log_in(email: str, password: str) -> str:
    """Tests logging in functionality"""
    endpoint = f"{BASE_URL}/sessions"
    payload = {"email": email, "password": password}
    resp = requests.post(endpoint, data=payload)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "logged in"}
    return resp.cookies.get("session_id")


def profile_unlogged() -> None:
    """Tests profile information retrieval when not logged in"""
    endpoint = f"{BASE_URL}/profile"
    resp = requests.get(endpoint)
    assert resp.status_code == 403


def profile_logged(session_id: str) -> None:
    """Tests profile information retrieval when logged in"""
    endpoint = f"{BASE_URL}/profile"
    payload = {"session_id": session_id}
    resp = requests.get(endpoint, cookies=payload)
    assert resp.status_code == 200
    assert "email" in resp.json()


def log_out(session_id: str) -> None:
    """Test logging out functionality"""
    endpoint = f"{BASE_URL}/sessions"
    payload = {"session_id": session_id}
    resp = requests.delete(endpoint, cookies=payload)
    assert resp.status_code == 200
    assert resp.json() == {"message": "Bienvenue"}


def reset_password_token(email: str) -> str:
    """Tests password reset token generation"""
    endpoint = f"{BASE_URL}/reset_password"
    payload = {"email": email}
    resp = requests.post(endpoint, data=payload)
    assert resp.status_code == 200
    assert "email" in resp.json()
    assert resp.json()["email"] == email
    assert "reset_token" in resp.json()
    return resp.json().get("reset_token")


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Tests updating user password functionality"""
    endpoint = f"{BASE_URL}/reset_password"
    payload = {"email": email, "reset_token": reset_token,
               "new_password": new_password}
    resp = requests.put(endpoint, data=payload)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "Password updated"}


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
