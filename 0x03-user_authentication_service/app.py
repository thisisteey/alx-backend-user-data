#!/usr/bin/env python3
"""Flask application with user authentication features"""
from flask import Flask, jsonify


app = Flask(__name__)


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """Content of the home page"""
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
