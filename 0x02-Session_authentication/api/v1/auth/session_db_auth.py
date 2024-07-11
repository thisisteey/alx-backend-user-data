#!/usr/bin/env python3
"""Module for managing API session authentication expiration & storage ops"""
from .session_exp_auth import SessionExpAuth
from models.user_session import UserSession
from datetime import datetime, timedelta


class SessionDBAuth(SessionExpAuth):
    """Class for handling session authentication expiration & storage ops"""

    def create_session(self, user_id=None) -> str:
        """Generates & stores a session ID for the user, saving it in the db"""
        session_id = super().create_session(user_id)
        if type(session_id) == str:
            sessionInfo = {
                    "user_id": user_id,
                    "session_id": session_id
            }
            userSess = UserSession(**sessionInfo)
            userSess.save()
            return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """Gets the user id linked with a given session id & creation time"""
        try:
            sessionDict = UserSession.search({"session_id": session_id})
        except Exception:
            return None
        if len(sessionDict) <= 0:
            return None
        currTime = datetime.now()
        sessSpan = timedelta(seconds=self.session_duration)
        expryTime = sessionDict[0].created_at + sessSpan
        if expryTime < currTime:
            return None
        return sessionDict[0].user_id

    def destroy_session(self, request=None) -> bool:
        """Deletes an authenticated session"""
        session_id = self.session_cookie(request)
        try:
            sessionDict = UserSession.search({"session_id": session_id})
        except Exception:
            return False
        if len(sessionDict) <= 0:
            return False
        sessionDict[0].remove()
        return True
