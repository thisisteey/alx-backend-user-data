#!/usr/bin/env python3
"""Module for encrypting password securely using bcrypt"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Gets and returns a salted, hashed password using bcrypt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
