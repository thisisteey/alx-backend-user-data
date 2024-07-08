#!/usr/bin/env python3
"""Module for managing API basic authentication operations"""
from .auth import Auth
import re
import base64
import binascii
from typing import Tuple, TypeVar
from models.user import User


class BasicAuth(Auth):
    """Class for handling basic authentication operations"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Get & return the base64 token from the auth header for basic auth"""
        if type(authorization_header) == str:
            regexPtrn = r"Basic (?P<token>.+)"
            fldMtch = re.fullmatch(regexPtrn, authorization_header.strip())
            if fldMtch is not None:
                return fldMtch.group("token")
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """Converts a base64-encoded auth header into a decoed string"""
        if type(base64_authorization_header) == str:
            try:
                decodedBytes = base64.b64decode(base64_authorization_header,
                                                validate=True)
                return decodedBytes.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Extracts username & password from a decoded base64 auth header"""
        if type(decoded_base64_authorization_header) == str:
            regexPtrn = r"(?P<user>[^:]+):(?P<password>.+)"
            fldMtch = re.fullmatch(regexPtrn,
                                   decoded_base64_authorization_header.strip())
            if fldMtch is not None:
                usr = fldMtch.group("user")
                pwd = fldMtch.group("password")
                return usr, pwd
        return None, None

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Get & return user based on user's auth information"""
        if type(user_email) == str and type(user_pwd) == str:
            try:
                mtchUsers = User.search({"email": user_email})
            except Exception:
                return None
            if len(mtchUsers) <= 0:
                return None
            if mtchUsers[0].is_valid_password(user_pwd):
                return mtchUsers[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Gets & returns the current user based on request"""
        authHeader = self.authorization_header(request)
        b64Token = self.extract_base64_authorization_header(authHeader)
        decodedToken = self.decode_base64_authorization_header(b64Token)
        email, pwd = self.extract_user_credentials(decodedToken)
        return self.user_object_from_credentials(email, pwd)
