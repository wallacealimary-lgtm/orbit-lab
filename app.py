

import os
import secrets

from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

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
