from fortigate_api import FortiGateAPI
import os
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("FW_ADDRESS")
TOKEN = os.getenv("API_TOKEN")

def createAPI():
    api = FortiGateAPI(
        host=HOST,
        token=TOKEN,
        scheme="https",
        port=443,
    )
    return api

