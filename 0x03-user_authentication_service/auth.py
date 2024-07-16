#!/usr/bin/env python3
"""Module for managing authentication-related routines"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """Encrypts and return salted hash of a password"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Gets and returns a unique uuid"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initializes an instance of Auth"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Creates and stores a new user in the database"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Verifies the validity of a user's login details"""
        userRecord = None
        try:
            userRecord = self._db.find_user_by(email=email)
            if userRecord is not None:
                return bcrypt.checkpw(password.encode("utf-8"),
                                      userRecord.hashed_password)
        except NoResultFound:
            return False
        return False
