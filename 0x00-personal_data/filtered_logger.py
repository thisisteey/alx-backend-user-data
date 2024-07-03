#!/usr/bin/env python3
"""Module that handles log filtering"""
import logging
import re
from typing import List
import os
import mysql.connector


regexPatrns = {
        'extract': lambda flds, sep: fr"(?P<field>{'|'.join(flds)})=[^{sep}]*",
        'replace': lambda redact: fr"\g<field>={redact}"
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


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


def get_logger() -> logging.Logger:
    """Creates and configures a logger specifically for a user data"""
    userDatalogger = logging.getLogger("user_data")
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(RedactingFormatter(PII_FIELDS))
    userDatalogger.setLevel(logging.INFO)
    userDatalogger.propagate = False
    userDatalogger.addHandler(streamHandler)
    return userDatalogger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Gets and returns a connector to the database"""
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    conn = mysql.connector.connection.MySQLConnection(
            user=db_user,
            password=db_pwd,
            host=db_host,
            database=db_name
    )
    return conn


def main():
    """Logs user record information fetched from a database table"""
    fieldNames = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fieldNames.split(",")
    dbqry = f"SELECT {fieldNames} FROM users;"
    infoLogger = get_logger()
    conn = get_db()
    with conn.cursor() as cursor:
        cursor.execute(dbqry)
        rows = cursor.fetchall()
        for row in rows:
            logData = map(lambda x: f"{x[0]}={x[1]}", zip(columns, row))
            logMsg = f"{'; '.join(list(logData))};"
            args = ("user_data", logging.INFO, None, None, logMsg, None, None)
            logrecord = logging.LogRecord(*args)
            infoLogger.handle(logrecord)


if __name__ == "__main__":
    main()
