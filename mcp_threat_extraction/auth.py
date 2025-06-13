"""
Firebase認証モジュール
"""

import os
import json
from typing import Optional, Dict, Any
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import firebase_admin
from firebase_admin import credentials, auth
from dotenv import load_dotenv

load_dotenv()

# Firebase Admin SDK の初期化
_firebase_app = None

def initialize_firebase():
    """Firebase Admin SDKを初期化"""
    global _firebase_app
    
    if _firebase_app is not None:
        return _firebase_app
    
    try:
        # 環境変数からFirebase設定を読み込み
        firebase_config = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY")
        
        if firebase_config:
            if firebase_config.startswith('{'):
                # JSON文字列の場合
                service_account_info = json.loads(firebase_config)
                cred = credentials.Certificate(service_account_info)
                print("Firebase initialized with JSON credentials from environment variable")
            else:
                # ファイルパスの場合
                if os.path.exists(firebase_config):
                    cred = credentials.Certificate(firebase_config)
                    print(f"Firebase initialized with credentials file: {firebase_config}")
                else:
                    raise FileNotFoundError(f"Firebase service account file not found: {firebase_config}")
        else:
            # 他の環境変数オプションを試す
            project_id = os.getenv("FIREBASE_PROJECT_ID")
            private_key = os.getenv("FIREBASE_PRIVATE_KEY")
            client_email = os.getenv("FIREBASE_CLIENT_EMAIL")
            
            if project_id and private_key and client_email:
                # 個別の環境変数から認証情報を構築
                service_account_info = {
                    "type": "service_account",
                    "project_id": project_id,
                    "private_key": private_key.replace('\\n', '\n'),
                    "client_email": client_email,
                    "client_id": os.getenv("FIREBASE_CLIENT_ID", ""),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{client_email}"
                }
                cred = credentials.Certificate(service_account_info)
                print("Firebase initialized with individual environment variables")
            else:
                # デフォルトの認証情報を使用（Google Cloud環境など）
                cred = credentials.ApplicationDefault()
                print("Firebase initialized with application default credentials")
        
        _firebase_app = firebase_admin.initialize_app(cred)
        print("Firebase Admin SDK initialized successfully")
        return _firebase_app
        
    except Exception as e:
        print(f"Firebase initialization failed: {e}")
        # 開発環境では認証を無効化する場合
        if os.getenv("DISABLE_AUTH", "false").lower() == "true":
            print("Authentication disabled for development")
            return None
        raise

# HTTPBearer認証スキーム
security = HTTPBearer(auto_error=False)

async def verify_firebase_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[Dict[str, Any]]:
    """
    Firebase IDトークンを検証する
    
    Returns:
        Dict[str, Any]: デコードされたトークンの情報、認証が無効の場合はNone
    """
    # 認証が無効化されている場合
    if os.getenv("DISABLE_AUTH", "false").lower() == "true":
        return {"uid": "dev-user", "email": "dev@example.com"}
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="認証トークンが必要です",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Firebase Admin SDKでトークンを検証
        decoded_token = auth.verify_id_token(credentials.credentials)
        return decoded_token
    except auth.InvalidIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="無効な認証トークンです",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except auth.ExpiredIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="認証トークンが期限切れです",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        print(f"Token verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="認証に失敗しました",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token_data: Dict[str, Any] = Depends(verify_firebase_token)) -> Dict[str, Any]:
    """
    現在のユーザー情報を取得
    """
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー情報を取得できません"
        )
    
    return {
        "uid": token_data.get("uid"),
        "email": token_data.get("email"),
        "name": token_data.get("name"),
        "email_verified": token_data.get("email_verified", False)
    }

async def require_auth(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    認証を必須とする依存関数
    """
    return current_user

