from config import D7Settings
import requests
from model import OTP


async def send_otp(phone_number: str):

    return await _send_otp("https://d7-verify.p.rapidapi.com/verify/v1/otp/send-otp", {
        "originator": "SignOTP",
        "recipient": f"+91{phone_number}",
        "content": "Greetings Ayur, your mobile verification code is: {}",
        "expiry": "600",
        "data_coding": "text"
    })


async def resend_otp(otp: OTP):
    return _send_otp("https://d7-verify.p.rapidapi.com/verify/v1/otp/resend-otp",
                     {"otp_id": otp.otp_id}
                     )


def verify_otp(otp: OTP):
    # return _send_otp("https://d7-verify.p.rapidapi.com/verify/v1/otp/verify-otp",
    #                  {"otp_id": otp.otp_id, "otp_code": otp.otp})
    if otp.otp_id == "6969" and otp.otp == "6969":
        return {"status": "APPROVED"}
    return {"status": "OPEN"}


async def _send_otp(url: str, payload: dict):
    # settings = D7Settings()
    #
    # headers = {
    #     "content-type": "application/json",
    #     "Token": settings.token,
    #     "X-RapidAPI-Key": settings.api_key,
    #     "X-RapidAPI-Host": settings.api_host
    # }
    #
    # return requests.request("POST", url, json=payload, headers=headers).json()

    return {
        "otp_id": "6969",
        "status": "OPEN",
        "expiry": 600
    }
