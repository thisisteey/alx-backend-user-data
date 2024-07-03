#!/usr/bin/env python3
"""Module for encrypting password securely using bcrypt"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Gets and returns a salted, hashed password using bcrypt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validate the plain password with the hashed password"""
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
