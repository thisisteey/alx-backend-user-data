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


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialise the RedactingFormatter class"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a LogRecord and obfuscate specified fields"""
        fmtMsg = super(RedactingFormatter, self).format(record)
        redactMsg = filter_datum(self.fields, self.REDACTION,
                                 fmtMsg, self.SEPARATOR)
        return redactMsg
