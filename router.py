from fastapi import Depends, HTTPException, status, APIRouter, Request
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta
from jose import jwt, JWTError
from config import JWT_Settings
from functools import lru_cache
from utils.database import DataBase
import exceptions as exceptions
from pymongo import errors
from token import create_access_token, validate_token
import math
from utils import generate_uuid
from pydantic.validators import dict_validator
from pydantic import EmailStr
from user_data.model import UserData
from model import User, UserToken, UserLogin, UserSignUp, StaffLogin, StaffSignUp, OTP, Token, StaffToken, Staff
from utils.password import hash_password
from utils.otp import send_otp, resend_otp, verify_otp

auth_router = APIRouter()


def get_user(user: User) -> dict:
    
    """
    Will return user data either on the basis of phone_number or ayur_i
    """
    
    if not user["phone_number"] or not user["ayur_id"]:
        raise exceptions.HTTP_400()
    _user = DataBase().session.ayur.user.find_one(
        {"$or": [{'ayur_id': user["ayur_id"]}, {'phone_number': user["phone_number"]}]})
    if not _user:
        raise exceptions.HTTP_404()
    return _user


def _get_staff(staff_username: str) -> Staff:
    staff = DataBase().session.auth.hospital_staff.find_one({"username": staff_username})
    if not staff:
        raise exceptions.HTTP_404("username not found")
    return Staff(**staff)


def login_staff(staff: StaffLogin) -> Dict[str, str]:
    password = hash_password(staff.password)
    staff = _get_staff(staff.username)
    if staff.password != password:
        raise exceptions.HTTP_401("Invalid Username or Password")

    access_token = create_access_token(
        data={"sub": staff.username, "aud": "hospital", "hospital_id": staff.hospital_id, "is_admin": staff.is_admin,
              "access": staff.access.split(";")},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "Bearer"}


# This function will verify the user OTP...
def authenticate_user(user_login: UserLogin):
    
    user = get_user(user_login)  # check if user exist in db

    if not verify_otp(user_login.otp):
        raise exceptions.HTTP_401()
    return user


@auth_router.post("/check_token", tags=["token"], status_code=status.HTTP_200_OK)
async def hospital(token: dict = Depends(validate_token)) -> Dict[str, str]:
    return {"is_valid": True}


# To generate a new token after logging in
@auth_router.post("/login/user", tags=["users"], status_code=status.HTTP_200_OK)
async def login(data: UserLogin):

    _user: User = authenticate_user(data)  # Verify the credentials
    if not _user:
        raise HTTPException(status_code=403, detail="Invalid Token")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Create an access token with data containing username of the user and the expiry time of the token
    access_token = create_access_token(
        data={"sub": _user["user_id"], "phone_number": _user["phone_number"], "aud": "user"},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "Bearer"}


@auth_router.post("/register/user", tags=["users"], status_code=status.HTTP_201_CREATED)
def register(user_data: UserSignUp):
    session = DataBase().session.ayur
    if session.user.find_one({"phone_number": phone_number}):  # TODO check fingerprint
        raise exceptions.HTTP_409_CONFLICT
    if verify_otp(otp):
        tries = 5
        while tries > 0:
            ayur_id = generate_uuid()
            if session.user.find_one({"ayur_id": ayur_id}):
                tries -= 1
                continue
            session.user.insert_one({"phone_number": F"+91{phone_number}", "ayur_id": ayur_id})
            user_data.ayur_id = ayur_id
            session.user.insert_one(user_data.dict())
            return {"ayur_id": ayur_id}

        raise exceptions.HTTP_503_SERVICE_UNAVAILABLE


@auth_router.post("/register/hospital_staff", tags=["hospital"], status_code=status.HTTP_201_CREATED)
def register_hospital_staff(staff: StaffSignUp, token_data: StaffToken = Depends(validate_token)):
    
    if not token_data.is_admin:  # only admins can create new users
        raise exceptions.HTTP_403()
        
    session = DataBase.session.auth.hospital_staff
    if session.find_one({"username": staff.username}):
        raise exceptions.HTTP_409("username already exist!")
    password = hash_password(staff.password)

    session.insert_one({"hospital_id": staff.hospital_id, "username": staff.username,
                        "password": password, "is_admin": staff.is_admin, "access": staff.access})


@auth_router.post("/login/hospital_staff", tags=["hospital"], status_code=status.HTTP_200_OK)
def login_hospital_staff(staff: StaffLogin):
    return login_staff(staff)


@auth_router.post("/otp/send", tags=["OTP"], status_code=status.HTTP_200_OK)
async def create_otp(user_cred: User):
    """
    Send OTP to phone number
    if user_id is received, retrieve phone number from database and send OTP
    """

    if not user_cred.phone_number:
        user_cred.phone_number = get_user(user_cred)["phone_number"]
        
    return await send_otp(user_cred.phone_number)


@auth_router.post("/otp/resend", tags=["OTP"], status_code=status.HTTP_200_OK)
async def re_send_otp(otp: OTP):
    return resend_otp(otp)


@auth_router.get("/public_keys")
def get_public_keys():
    ...
