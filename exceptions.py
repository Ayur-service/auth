from fastapi import HTTPException
from starlette import status


def HTTP_400(msg: str = "one or more field is not present") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=msg
    )


def HTTP_403(msg: str = "Forbidden") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=msg
    )


def HTTP_409(msg: str = "Data already exist") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=msg
    )


def HTTP_422(msg: str = "Unprocessable Entity") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=msg
    )


def HTTP_401(msg: str = "UnAuthorized") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=msg
    )


def HTTP_404(msg: str = "Not found") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=msg
    )


def HTTP_500(msg: str = "Internal Server ERROR") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=msg
    )


def HTTP_503(msg: str = "Service Unavailable") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=msg
    )


def INVALID_ARGS(msg: str = "Insufficient Arguments") -> Exception:
    return Exception(msg)
