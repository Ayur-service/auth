from pydantic import BaseSettings, BaseModel
from pathlib import Path
from cryptography.hazmat.primitives import serialization


class AppSettings(BaseSettings):

    class Config:
        env_file = Path(__file__).parent.joinpath('.env').__str__()
        env_file_encoding = 'utf-8'


class DBSettings(AppSettings):
    db_name: str
    db_username: str
    db_password: str
    db_host: str = "localhost"


class JWT_Settings:
    secret_key_path: str = Path(__file__).parent.joinpath("./_auth")
    public_key_path: str = Path(__file__).parent.joinpath("./_auth.pub")

    secret_key: str = serialization.load_ssh_private_key(open(secret_key_path, "r").read().encode(), password=b"Kanak@don4")
    public_key: str = serialization.load_ssh_public_key(open(public_key_path, "r").read().encode())
    algorithm: str = "RS256"
    validity: int = 21600
    aud = ["hospital", "user"]


class OriginSettings(AppSettings):
    origin: str


class D7Settings(AppSettings):
    token: str
    api_key: str
    api_host: str

