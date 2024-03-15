# Copyright 2022 Cartesi Pte. Ltd.
#
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License. You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

from os import environ
import model
import cartesi_wallet.wallet as Wallet
import json
import traceback
import logging
import requests

from urllib.parse import urlparse

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = "http://localhost:8080/rollup"
if "ROLLUP_HTTP_SERVER_URL" in environ:
    rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")

erc20_portal_address = "0x9C21AEb2093C32DDbC53eEF24B873BDCd1aDa1DB"
token_address = "0xae7f61eCf06C65405560166b259C54031428A9C4"
dapp_relay_address = "0xF5DE34d6BbC0446E2a45719E718efEbaaE179daE"

wallet = Wallet
rollup_address = ""

def hex2str(hex):
    """
    Decodes a hex string into a regular string
    """
    return bytes.fromhex(hex[2:]).decode("utf-8")

def str2hex(str):
    """
    Encodes a string as a hex string
    """
    return "0x" + str.encode("utf-8").hex()


def decode_json(b):
    s = bytes.fromhex(b[2:]).decode("utf-8")
    d = json.loads(s)
    return d


def calculate_aqi(concentrations):
    """
       Calculates a simple Air Quality index by calculating the mean of sum of the values predicted for the core pollutants
    """
    aqi = sum(concentrations) / len(concentrations)
    return aqi

def categorize_aqi(aqi):
    """
           Categorizes the AQI Calculated in the Standard Air quality ranges from good to hazardous
    """
    if aqi <= 50:
        return 'Good'
    elif aqi <= 100:
        return 'Moderate'
    elif aqi <= 150:
        return 'Bad for sensible groups!'
    elif aqi <= 200:
        return 'Bad'
    elif aqi <= 300:
        return 'Very Bad'
    else:
        return 'Dangerous'


def format(input):
    """
    Transforms a given input so that it is in the format expected by the model
    """
    output = list(input.values())
    return output

def handle_advance(data):
    logger.info(f"Received advance request data {data}")
    msg_sender = data["metadata"]["msg_sender"]
    payload = data["payload"]

    if msg_sender.lower() == dapp_relay_address.lower():
        global rollup_address
        logger.info(f"Received advance from dapp relay")
        rollup_address = payload
        response = requests.post(
            rollup_server + "/notice", json={"payload": str2hex(f"Set rollup_address {rollup_address}")})
        return "accept"
    try:
        # depositing sunodo for processing
        if msg_sender.lower() == erc20_portal_address.lower():
            notice = wallet.erc20_deposit_process(payload)
            response = requests.post(
                rollup_server + "/notice", json={"payload": notice.payload})
    except Exception as e:
        status = "reject"
        msg = f"Error processing data {data}\n{traceback.format_exc()}"
        logger.error(msg)
        response = requests.post(rollup_server + "/report", json={"payload": str2hex(msg)})
        logger.info(f"Received report status {response.status_code} body {response.content}")
        return status
    
    try:
        req_json = decode_json(payload)
        print(req_json)
        if req_json["method"] == "erc20_withdraw":
            converted_value = int(req_json["amount"]) if isinstance(
            req_json["amount"], str) and req_json["amount"].isdigit() else req_json["amount"]
            voucher = wallet.erc20_withdraw(
            req_json["from"].lower(), req_json["erc20"].lower(), converted_value)
            response = requests.post(rollup_server + "/voucher", json={
            "payload": voucher.payload, "destination": voucher.destination})
        else:
            if (wallet.balance_get(msg_sender).erc20_get(token_address.lower()) != 0):
                input = hex2str(data["payload"])
                logger.info(f"Received input: '{input}'")

                # converts input to the format expected by the m2cgen model
                input_json = json.loads(input)
                input_formatted = format(input_json)

                # computes predicted classification for input
                predicted = categorize_aqi(
                    calculate_aqi(model.score(input_formatted)))
                logger.info(f"Data={input}, Predicted: {predicted}")

                # emits output notice with predicted class name
                output = str2hex(str(predicted))
                logger.info(f"Adding notice with payload: {predicted}")
                response = requests.post(
                    rollup_server + "/notice", json={"payload": output})
                logger.info(
                    f"Received notice status {response.status_code} body {response.content}")
            else:
                status = "reject"
                msg = f"Insuficient Funds for the user : {msg_sender}"
                logger.error(msg)
                response = requests.post(
                    rollup_server + "/report", json={"payload": str2hex(msg)})
                logger.info(
                    f"Received report status {response.status_code} body {response.content}")
        return "accept"
    except Exception as error:
        error_msg = f"Failed to process command '{payload}'. {error}"
        response = requests.post(
        rollup_server + "/report", json={"payload": str2hex(error_msg)})
        logger.debug(error_msg, exc_info=True)
        return "reject"


def handle_inspect(data):
    logger.info(f"Received inspect request data {data}")
    try:
        url = urlparse(hex2str(data["payload"]))
        if url.path.startswith("balance/"):
            info = url.path.replace("balance/", "").split("/")
            token_type, account = info[0].lower(), info[1].lower()
            token_address, token_id, amount = "", 0, 0

            if (token_type == "ether"):
                amount = wallet.balance_get(account).ether_get()
            elif (token_type == "erc20"):
                token_address = info[2]
                amount = wallet.balance_get(
                    account).erc20_get(token_address.lower())
            elif (token_type == "erc721"):
                token_address, token_id = info[2], info[3]
                amount = 1 if token_id in wallet.balance_get(
                    account).erc721_get(token_address.lower()) else 0

            report = {"payload": str2hex(
                {"token_id": token_id, "amount": amount, "token_type": token_type})}
            response = requests.post(rollup_server + "/report", json=report)
            logger.info(
                f"Received report status {response.status_code} body {response.content}")
        return "accept"
    except Exception as error:
        error_msg = f"Failed to process inspect request. {error}"
        logger.debug(error_msg, exc_info=True)
        return "reject"


handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]
        
        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])