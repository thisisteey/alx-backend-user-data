#!/usr/bin/env python3
"""Module that handles log filtering"""
import logging
import re
from typing import List


regexPatrns = {
        'extract': lambda flds, sep: fr"(?P<field>{'|'.join(flds)})=[^{sep}]*",
        'replace': lambda redact: fr"\g<field>={redact}"
}


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Gets and returns an obfuscated log message"""
    extract, replace = (regexPatrns["extract"], regexPatrns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)
