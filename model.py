from pydantic import BaseModel, validator
from typing import List, Optional


class OTP(BaseModel):
    otp_id: str
    otp: str = None


class BaseUser(BaseModel):
    phone_number: str
    fingerprint_hash: str

    @validator("phone_number")
    def validate_phone_number(cls, phone_number: str):
        if phone_number[0] not in ["7", "8", "9"]:
            raise ValueError("Invalid Phone Number: Number should start from either 7, 8, or 9")
        if len(phone_number) != 10:
            raise ValueError("Invalid Phone Number: Number should be of length 10")

        return phone_number


class User(BaseUser):
    ayur_id: str


class UserLogin(BaseModel):
    ayur_id: Optional[str]
    phone_number: Optional[str]
    fingerprint_hash: Optional[str]
    otp: OTP


class UserSignUp(BaseUser):
    otp: OTP


class BaseStaff(BaseModel):
    username: str
    password: str


class Staff(BaseStaff):
    hospital_id: str
    is_admin: bool
    access: List[str]


class AdminStaff(Staff):
    is_admin: bool = True
    access: List[str] = ["Read", " Write"]


class StaffLogin(BaseStaff):
    hospital_id: str


class StaffSignUp(BaseStaff):
    password2: str
    is_admin: bool = False
    access: List[str] = ["read"]  # write, read

    @validator("password2")
    def verify_password(cls, v, values,  **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('passwords do not match')
        return v


class Token(BaseModel):
    sub: str  # user_id or staff_id
    aud: str  # issued to whom (hospital or  user)
    expire: int


class UserToken(Token):
    phone_number: Optional[str]


class StaffToken(Token):
    hospital_id: Optional[str]
    is_admin: bool = False
    access: List[str]

