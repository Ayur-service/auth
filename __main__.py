from utils.database import DataBase
from model import AdminStaff
from typing import Optional, List
from logging import error
import sys
import exceptions
import getopt
from pathlib import Path
from utils.password import hash_password
from utils.database import HospitalStaff


def cmd():
    if len(sys.argv) <= 1:
        raise exceptions.INVALID_ARGS()
    try:
        return _CMDS[sys.argv[1]]()
    except KeyError:
        raise Exception("Invalid Argument")


def create_admin():
    hospital_id = input("Hospital_id: ")
    username = input("username: ")
    password = input("password: ")
    password2 = input("password2: ")

    if password != password2:
        raise Exception("Password1 doesn't match Password2")

    _create_admin(AdminStaff(hospital_id=hospital_id, username=username, password=password))


def _create_admin(staff: AdminStaff) -> Optional[Exception]:
    try:

        hash_pwd = hash_password(staff.password)
        DataBase().session.add(HospitalStaff(hospital_id=staff.hospital_id, password=hash_pwd, username=staff.username,
                                             is_admin=staff.is_admin, access=staff.access))
        DataBase().session.commit()

    except Exception as msg:
        error(msg)
        raise Exception(msg)


_CMDS: List[str] = {"--create-admin": create_admin}

if __name__ == "__main__":
    cmd()
