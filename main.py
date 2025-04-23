from fastapi import FastAPI, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseModel, BaseSettings
from fastapi.middleware.cors import CORSMiddleware
from passlib.hash import bcrypt
from jose import JWTError
from typing import List

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

fake_users_db = {
    "kevin": {"username": "kevin", "password": bcrypt.hash("muaythai")}
}

# JWT Config
class Settings(BaseSettings):
    authjwt_secret_key: str = "supersecretkey"

@AuthJWT.load_config
def get_config():
    return Settings()

class User(BaseModel):
    username: str
    password: str

class ProtectedData(BaseModel):
    msg: str

@app.post("/login")
def login(user: User, Authorize: AuthJWT = Depends()):
    db_user = fake_users_db.get(user.username)
    if not db_user or not bcrypt.verify(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}

@app.get("/protected", response_model=ProtectedData)
def protected(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
    except AuthJWTException as e:
        raise HTTPException(status_code=401, detail="Token missing or invalid")
    
    current_user = Authorize.get_jwt_subject()
    return {"msg": f"Hello {current_user}, this is protected data!"}