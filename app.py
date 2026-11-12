
import os
import secrets

import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE")


@app.get("/hello")
def say_hello():
    return {"message": "Hello from Orbit!"}


@app.get("/secret")
def get_secret(x_api_key: str | None = Header(default=None)):
    expected_key = os.environ.get("ORBIT_API_KEY")

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured"
        )

    if not x_api_key or not secrets.compare_digest(
        x_api_key, expected_key
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )

    return {"message": "Welcome to the protected Orbit API!"}


@app.get("/oauth-protected")
def oauth_protected(
    authorization: str | None = Header(default=None)
):
    if not AUTH0_DOMAIN or not AUTH0_AUDIENCE:
        raise HTTPException(
            status_code=503,
            detail="OAuth is not configured"
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing bearer token"
        )

    token = authorization.removeprefix("Bearer ").strip()

    try:
        jwks_client = PyJWKClient(
            f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        )
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUTH0_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )

    except (jwt.PyJWTError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired bearer token"
        )

    scopes = payload.get("scope", "").split()

    if "read:orbit" not in scopes:
        raise HTTPException(
            status_code=403,
            detail="Missing read:orbit permission"
        )

    return {
        "message": "OAuth authentication successful!",
        "application": payload.get("sub"),
        "permissions": scopes
    }
