"""
Vercel Serverless Function Entry Point for MalwSentinel
Exposes the Starlette ASGI application for Vercel's Python runtime.
"""

import sys
import os

# Ensure the root project directory is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from server import app
