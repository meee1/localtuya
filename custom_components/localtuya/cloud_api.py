"""Class to perform requests to Tuya Cloud APIs."""
import functools
import hashlib
import hmac
import json
import logging
import time

import requests

from .common import TuyaDevice, async_config_entry_by_device_id

from homeassistant.const import (
    CONF_DEVICES
)

_LOGGER = logging.getLogger(__name__)


# Signature algorithm.
def calc_sign(msg, key):
    """Calculate signature for request."""
    sign = (
        hmac.new(
            msg=bytes(msg, "latin-1"),
            key=bytes(key, "latin-1"),
            digestmod=hashlib.sha256,
        )
        .hexdigest()
        .upper()
    )
    return sign


class TuyaCloudApi:
    """Class to send API calls."""

    def __init__(self, hass, region_code, client_id, secret, user_id):
        """Initialize the class."""
        self._hass = hass
        self._base_url = f"https://openapi.tuya{region_code}.com"
        self._client_id = client_id
        self._secret = secret
        self._user_id = user_id
        self._access_token = ""
        self.device_list = {}

    def generate_payload(self, method, timestamp, url, headers, body=None):
        """Generate signed payload for requests."""
        payload = self._client_id + self._access_token + timestamp

        payload += method + "\n"
        # Content-SHA256
        payload += hashlib.sha256(bytes((body or "").encode("utf-8"))).hexdigest()
        payload += (
            "\n"
            + "".join(
                [
                    "%s:%s\n" % (key, headers[key])  # Headers
                    for key in headers.get("Signature-Headers", "").split(":")
                    if key in headers
                ]
            )
            + "\n/"
            + url.split("//", 1)[-1].split("/", 1)[-1]  # Url
        )
        # _LOGGER.debug("PAYLOAD: %s", payload)
        return payload

    async def async_make_request(self, method, url, body=None, headers={}):
        """Perform requests."""
        timestamp = str(int(time.time() * 1000))
        payload = self.generate_payload(method, timestamp, url, headers, body)
        default_par = {
            "client_id": self._client_id,
            "access_token": self._access_token,
            "sign": calc_sign(payload, self._secret),
            "t": timestamp,
            "sign_method": "HMAC-SHA256",
        }
        full_url = self._base_url + url
        # _LOGGER.debug("\n" + method + ": [%s]", full_url)

        if method == "GET":
            func = functools.partial(
                requests.get, full_url, headers=dict(default_par, **headers)
            )
        elif method == "POST":
            func = functools.partial(
                requests.post,
                full_url,
                headers=dict(default_par, **headers),
                data=json.dumps(body),
            )
            # _LOGGER.debug("BODY: [%s]", body)
        elif method == "PUT":
            func = functools.partial(
                requests.put,
                full_url,
                headers=dict(default_par, **headers),
                data=json.dumps(body),
            )

        resp = await self._hass.async_add_executor_job(func)
        # r = json.dumps(r.json(), indent=2, ensure_ascii=False) # Beautify the format
        return resp

    async def async_get_access_token(self):
        """Obtain a valid access token."""
        try:
            resp = await self.async_make_request("GET", "/v1.0/token?grant_type=1")
        except requests.exceptions.ConnectionError:
            return "Request failed, status ConnectionError"

        if not resp.ok:
            return "Request failed, status " + str(resp.status)

        r_json = resp.json()
        if not r_json["success"]:
            return f"Error {r_json['code']}: {r_json['msg']}"

        self._access_token = resp.json()["result"]["access_token"]
        return "ok"

    async def async_get_devices_list(self):
        """Obtain the list of devices associated to a user."""
        resp = await self.async_make_request(
            "GET", url=f"/v1.0/users/{self._user_id}/devices"
        )

        if not resp.ok:
            return "Request failed, status " + str(resp.status)

        r_json = resp.json()
        if not r_json["success"]:
            # _LOGGER.debug(
            #     "Request failed, reply is %s",
            #     json.dumps(r_json, indent=2, ensure_ascii=False)
            # )
            return f"Error {r_json['code']}: {r_json['msg']}"

        self.device_list = {dev["id"]: dev for dev in r_json["result"]}
        # _LOGGER.debug("DEV_LIST: %s", self.device_list)

        return "ok"

    async def async_get_device_dps(self, deviceid):
        resp = await self.async_make_request(
            "GET", url=f"/v2.0/cloud/thing/{deviceid}/shadow/properties"
        )

        if not resp.ok:
            return "Request failed, status " + str(resp.status)

        r_json = resp.json()
        if not r_json["success"]:
            # _LOGGER.debug(
            #     "Request failed, reply is %s",
            #     json.dumps(r_json, indent=2, ensure_ascii=False)
            # )
            return f"Error {r_json['code']}: {r_json['msg']}"

        self.device_list[deviceid]["device_dps"] = {r_json["result"]["properties"]}
        _LOGGER.debug("device_dps: %s %s", deviceid, self.device_list[deviceid]["device_dps"])

        return "ok"
    
    async def async_get_device_data_model(self):
                
        for device_id in self.device_list:
            # If device is not in cache, check if a config entry exists
            entry = async_config_entry_by_device_id(hass, device_id)
            if entry is None:
                return

            dev_entry = entry.data[CONF_DEVICES][device_id]

            if "data_model" in dev_entry:
                _LOGGER.debug("data_model no update needed")
                return

            new_data = entry.data.copy()

            resp = await self.async_make_request(
                "GET", url=f"/v2.0/cloud/thing/{deviceid}/model"
            )

            if not resp.ok:
                return "Request failed, status " + str(resp.status)

            r_json = resp.json()
            if not r_json["success"]:
                # _LOGGER.debug(
                #     "Request failed, reply is %s",
                #     json.dumps(r_json, indent=2, ensure_ascii=False)
                # )
                return f"Error {r_json['code']}: {r_json['msg']}"

            #_LOGGER.debug(
            #        "async_get_device_data_model, %s reply is %s", deviceid,
            #        json.dumps(r_json, indent=2, ensure_ascii=False)
            #)
            try:
                new_data[CONF_DEVICES][device_id]["data_model"] = json.loads(r_json["result"]["model"])

                new_data[ATTR_UPDATED_AT] = str(int(time.time() * 1000))
                #hass.config_entries.async_update_entry(entry, data=new_data)

                _LOGGER.debug("data_model: %s %s", device_id, new_data[CONF_DEVICES][device_id]["data_model"])
            except Exception as e:
                _LOGGER.info(e)
                pass

        return "ok"
