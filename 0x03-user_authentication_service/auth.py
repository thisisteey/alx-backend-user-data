#!/usr/bin/env python3
"""Module for managing authentication-related routines"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union


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

    def create_session(self, email: str) -> str:
        """Creates a new session for a given user"""
        userRecord = None
        try:
            userRecord = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if userRecord is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(userRecord.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets and returns a user using session ID"""
        userRecord = None
        if session_id is None:
            return None
        try:
            userRecord = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return userRecord

    def destroy_session(self, user_id: int) -> None:
        """Terminates session linked to a specific user"""
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Creates a password reset token for the specified email"""
        userRecord = None
        try:
            userRecord = self._db.find_user_by(email=email)
        except NoResultFound:
            userRecord = None
        if userRecord is None:
            raise ValueError()
        pwdResetTok = _generate_uuid()
        self._db.update_user(userRecord.id, reset_token=pwdResetTok)
        return pwdResetTok

    def update_password(self, reset_token: str, password: str) -> None:
        """Resets the user's password using a provided reset token"""
        userInst = None
        try:
            userInst = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            userInst = None
        if userInst is None:
            raise ValueError()
        newPWDhash = _hash_password(password)
        self._db.update_user(userInst.id, hashed_password=newPWDhash,
                             reset_token=None)
