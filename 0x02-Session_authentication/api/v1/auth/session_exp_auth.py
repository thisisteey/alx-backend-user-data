#!/usr/bin/env python3
"""Module for managing API session authentication expiration operations"""
from .session_auth import SessionAuth
import os
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """Class for handling session authentication expiration operations"""

    def __init__(self) -> None:
        """Initialises the session authentication expiration class"""
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id=None) -> str:
        """Generates & stores a seesion id & creation time for a given user"""
        session_id = super().create_session(user_id)
        if type(session_id) != str:
            return None
        self.user_id_by_session_id[session_id] = {
                "user_id": user_id,
                "created_at": datetime.now()
        }
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """Gets the user id linked with a given session id & creation time"""
        if session_id in self.user_id_by_session_id:
            sessionDict = self.user_id_by_session_id[session_id]
            if self.session_duration <= 0:
                return sessionDict["user_id"]
            if "created_at" not in sessionDict:
                return None
            currTime = datetime.now()
            sessSpan = timedelta(seconds=self.session_duration)
            expryTime = sessionDict["created_at"] + sessSpan
            if expryTime < currTime:
                return None
            return sessionDict["user_id"]
