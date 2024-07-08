#!/usr/bin/env python3
"""Module for managing API basic authentication operations"""
from .auth import Auth
import re
import base64
import binascii
from typing import Tuple


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
            except binascii.Error:
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
