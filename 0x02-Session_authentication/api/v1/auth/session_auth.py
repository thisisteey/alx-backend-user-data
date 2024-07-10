#!/usr/bin/env python3
"""Module for managing API session authentication operations"""
from .auth import Auth
from uuid import uuid4


class SessionAuth(Auth):
    """Class for handling session authentication operations"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Generates & stores a seesion id for a given user"""
        if type(user_id) is str:
            session_id = str(uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Gets & returns the user id associated with a given session id"""
        if type(session_id) is str:
            return self.user_id_by_session_id.get(session_id)