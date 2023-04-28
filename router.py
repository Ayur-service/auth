from fastapi import Depends, HTTPException, status, APIRouter, Request
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime, timedelta
from jose import jwt, JWTError
from config import JWT_Settings
from functools import lru_cache
from utils.database import DataBase, User as UserModel, HospitalStaff as HospitalStaffModel
import exceptions as exceptions
import math
from utils import generate_ayur_id
from pydantic.validators import dict_validator
from pydantic import EmailStr
from model import User, UserToken, UserLogin, UserSignUp, StaffLogin, StaffSignUp, OTP, Token, StaffToken, Staff
from utils.password import hash_password, verify_password
from utils.otp import send_otp, resend_otp, verify_otp
from _token import validate_token, create_access_token
from sqlalchemy import or_
from logging import info

auth_router = APIRouter()


def get_user(user: User) -> User:
    """
    Will return user data either on the basis of phone_number or ayur_id
    """

    session = DataBase().session

    if not user.phone_number and not user.ayur_id and not user.fingerprint_hash:
        raise exceptions.HTTP_400("Use AYUR_ID, phone_number or fingerprint to Log IN!")
    _user = session.query(UserModel).filter(
        or_(UserModel.phone_number == user.phone_number, UserModel.ayur_id == user.ayur_id,
            UserModel.fingerprint_hash == user.fingerprint_hash)).first()

    if not _user:
        raise exceptions.HTTP_404()
    return User(**_user.dict())


def _get_staff(staff_username: str) -> Staff:
    staff = DataBase().session.query(HospitalStaffModel).filter(HospitalStaffModel.username == staff_username).first()
    if not staff:
        raise exceptions.HTTP_404("username not found")
    return Staff(**staff.dict())


def login_staff(staff: StaffLogin) -> Dict[str, str]:
    staff = _get_staff(staff.username.lower())
    if not verify_password(staff.password, hash_password(staff.password)):
        raise exceptions.HTTP_401("Invalid Username or Password")

    access_token = create_access_token(
        data={"sub": staff.username, "aud": "hospital", "hospital_id": staff.hospital_id, "is_admin": staff.is_admin,
              "access": staff.access})
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

    # Create an access token with data containing username of the user and the expiry time of the token
    access_token = create_access_token(
        data={"sub": _user.ayur_id, "phone_number": _user.phone_number, "aud": "user"})
    return {"access_token": access_token, "token_type": "Bearer"}


@auth_router.post("/register/user", tags=["users"], status_code=status.HTTP_201_CREATED)
def register(user_data: UserSignUp):
    session = DataBase().session
    if session.query(UserModel).filter(or_(UserModel.fingerprint_hash == user_data.fingerprint_hash,
                                           UserModel.phone_number == user_data.phone_number)).first():
        raise exceptions.HTTP_409()
    if verify_otp(user_data.otp)["status"] == "APPROVED":
        tries = 5
        while tries > 0:
            ayur_id = str(generate_ayur_id())
            if session.query(UserModel).filter(UserModel.ayur_id == ayur_id).first():
                tries -= 1
                continue
            session.add(
                UserModel(phone_number=user_data.phone_number, ayur_id=ayur_id,
                          fingerprint_hash=user_data.fingerprint_hash))
            session.commit()
            return {"ayur_id": ayur_id}

        raise exceptions.HTTP_503()
    raise exceptions.HTTP_400("Invalid OTP")


@auth_router.post("/register/hospital_staff", tags=["hospital"], status_code=status.HTTP_201_CREATED)
def register_hospital_staff(staff: StaffSignUp, token_data: StaffToken = Depends(validate_token)):
    if not token_data.is_admin:  # only admins can create new users
        raise exceptions.HTTP_403()

    session = DataBase().session
    if session.query(HospitalStaffModel).filter(HospitalStaffModel.username == staff.username).first():
        raise exceptions.HTTP_409("username already exist!")

    session.add(HospitalStaffModel(hospital_id=token_data.hospital_id, username=staff.username.lower(),
                                   password=hash_password(staff.password),
                                   is_admin=staff.is_admin, access=staff.access))
    session.commit()

    info(f"{staff.username} is created with access: {staff.access}")


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
        user_cred.phone_number = get_user(user_cred).phone_number

    return await send_otp(user_cred.phone_number)


@auth_router.post("/otp/resend", tags=["OTP"], status_code=status.HTTP_200_OK)
async def re_send_otp(otp: OTP):
    return resend_otp(otp)


@auth_router.get("/public_keys")
def get_public_keys():
    ...

