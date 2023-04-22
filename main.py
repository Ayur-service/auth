from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import OriginSettings
from router import auth_router
from utils.database import DataBase
from utils.database import DataBase
from functools import lru_cache

app = FastAPI(
    title='Auth Service',
    description='Mere Mehboob Mere sanam',
    version='0.1',
    contact={
        "name": "MFtEK",
    },
    license_info={
        "name": "MIT",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
    },
    docs_url="/docs",
    redoc_url="/redocs"
)


@lru_cache()
def get_origin():
    return OriginSettings()


_origins = get_origin()


origin = [_origins.origin]

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin, "http://localhost:3000", "http://localhost:9000"],
    allow_credentials=True,
    allow_headers=['*', ],
    allow_methods=['*', ]
)


app.include_router(auth_router)
