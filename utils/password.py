from passlib.context import CryptContext

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return _pwd.hash(password)


def verify_password(plain_password, hashed_password):
    return _pwd.verify(plain_password, hashed_password)


if __name__ == "__main__":
    hp = hash_password("kanak")
    print(verify_password("kanak", hp))

