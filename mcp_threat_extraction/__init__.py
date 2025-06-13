"""
MCP Threat Extraction Server
医療機器の脅威記述文からCVSSスコアとセキュリティ特徴を抽出するMCPサーバー
"""

__version__ = "0.3.0"
__author__ = "Threat Assessment Team"

from .server import server, main

__all__ = ["server", "main"]