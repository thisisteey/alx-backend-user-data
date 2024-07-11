#!/usr/bin/env python3
"""Module for managing user sessions"""
from models.base import Base


class UserSession(Base):
    """Class representing user sessions"""

    def __init__(self, *args: list, **kwargs: dict) -> None:
        """Initialise the user session class"""
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get("user_id")
        self.session_id = kwargs.get("session_id")
