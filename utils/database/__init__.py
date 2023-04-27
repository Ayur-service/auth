from config import DBSettings
import logging
from datetime import datetime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import String, Column, create_engine, Index, CHAR, BOOLEAN, ARRAY
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from typing import List
from copy import deepcopy
from sqlalchemy import DDL, event

db = DBSettings()


class _Base(DeclarativeBase):

    def dict(self):
        return self.__dict__


class DBMeta(type):
    _instance = None

    def __call__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__call__(*args, **kwargs)
        return cls._instance


class DataBase(metaclass=DBMeta):

    db_name: str = db.db_name

    def __init__(self):
        self.engine = create_engine(
            f"postgresql://{db.db_username}:{db.db_password}@{db.db_host}/{db.db_name}",
            echo=False)
        event.listen(_Base.metadata, 'before_create', DDL(f"CREATE SCHEMA IF NOT EXISTS {self.db_name}"))

        _Base.metadata.create_all(bind=self.engine)
        self.session = sessionmaker(bind=self.engine)()
        logging.info("DB Instance created")


class User(_Base):
    __tablename__ = "users"
    ayur_id = Column("ayur_id", String(12), primary_key=True)  # Column (name_of_col_in_db, data_type, other_info)
    phone_number = Column("phone_number", String(10), nullable=False, index=True)  # create B index
    fingerprint_hash = Column("fp_hash", String(300), nullable=False, index=True)  # Create B index

    def __init__(self, ayur_id: str, phone_number: str, fingerprint_hash: str):
        self.ayur_id = ayur_id
        self.phone_number = phone_number
        self.fingerprint_hash = fingerprint_hash

    def __repr__(self):
        return '<User {0} - {1}>'.format(self.ayur_id, self.phone_number)


class HospitalStaff(_Base):
    __tablename__ = "hospital_staff"
    hospital_id = Column("hospital_id", String(15), primary_key=True)
    username = Column("username", String(15), primary_key=True)
    password = Column("password", String(300), nullable=False)
    is_admin = Column("is_admin", BOOLEAN, default=False)
    access = Column("access", ARRAY(String), nullable=False)

    def __init__(self, hospital_id: str, username: str, password: str, is_admin: bool = False, access: List[str] = ("read", )):
        self.hospital_id = hospital_id
        self.username = username
        self.password = password
        self.is_admin = is_admin
        self.access = access

    def __repr__(self):
        return '<Staff {0} - {1}>'.format(self.username, self.hospital_id)


# class Access(_Base):
#     __tablename__ = "access"
#     _id = Column("id", )

