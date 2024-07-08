#!/usr/bin/env python3
"""Module for managing API authentication operations"""
from flask import request
from typing import List, TypeVar
import re


class Auth:
    """Class for handling authentication operations"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Determines if a given path needs authentication"""
        if path is not None and excluded_paths is not None:
            for exclPath in map(lambda x: x.strip(), excluded_paths):
                mtchPtrn = ""
                if exclPath[-1] == "*":
                    mtchPtrn = f"{exclPath[0:-1]}.*"
                elif exclPath[-1] == "/":
                    mtchPtrn = f"{exclPath[0:-1]}/*"
                else:
                    mtchPtrn = f"{exclPath}/*"
                if re.match(mtchPtrn, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """Gets & returns the auth header from the incoming request"""
        if request is not None:
            return request.headers.get("Authorization", None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Identify the current user based on the request"""
        return None
