from functools import lru_cache
from config import JWT_Settings as _jwt
from jose import JWTError
import jwt
from typing import Dict
from datetime import timedelta, datetime
from fastapi import Request
import exceptions as exceptions
from model import UserToken, StaffToken
from jwt.exceptions import ExpiredSignatureError


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=_jwt.validity)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({'expire': expire.timestamp()})
    return jwt.encode(to_encode, _jwt.secret_key, _jwt.algorithm)


def decode_token(token: str) -> Dict[str, str]:
    return jwt.decode(token, _jwt.public_key, audience=_jwt.aud, algorithms=[_jwt.algorithm, ])


async def validate_token(request: Request) -> UserToken | StaffToken:
    try:
        token = request.headers["Authorization"]
        token = token.split(" ")
        if token[0] != "Bearer":
            raise exceptions.HTTP_400_MISSING_DATA

        token = decode_token(token[1])

        # if token["expire"] < datetime.utcnow().timestamp():

        return StaffToken(**token) if token["aud"] == "hospital" else UserToken(**token)

    except ExpiredSignatureError as e:
        logging.error(e)
        raise exceptions.HTTP_401("Expired Token")

    except JWTError as e:
        logging.error(e)
        raise exceptions.HTTP_401(e)

    except KeyError:  # when header is missing
        raise exceptions.HTTP_400("Required Headers are missing")
