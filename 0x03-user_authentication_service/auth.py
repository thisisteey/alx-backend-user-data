#!/usr/bin/env python3
"""Module for managing authentication-related routines"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """Encrypts and return salted hash of a password"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
