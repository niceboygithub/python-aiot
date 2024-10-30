"""Discovery.

This file contains the cloud api.
"""
import sys
import base64
import json
import logging
import pathlib
import time
import uuid
import re
import click
import requests
import rsa
from hashlib import md5
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

try:
    from rich import print as echo
except ImportError:
    echo = click.echo

try:
    from aiot.deviceinfo import DeviceInfo
except:
    from deviceinfo import DeviceInfo


_LOGGER = logging.getLogger(__name__)

URI = "https://aiot-rpc.aqara.cn"
USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
CONTENT_TYPE = "application/json; charset=utf-8"
APP_KEY = "523f61aa2f322134d0e71c40e928eb14"
APPID = '94549908487478b220992a70'
APP_VERSION = "2.3.3"
CLIENT_ID = "ALIa5eadb61ee9648a6b18ffd21b8fd264e"
LANG = "zh"
PHONE_ID = "091e0042b97c4a9ba46f4688a186c2d5"
PHONE_MODEL = "SM-N976N##Mobile"
NONCE_KEY = "A84B72400D23D0E0DFDD4C5FB552CF28"
SIGN_KEY = "1196eeaa12242821a9ea0b688d0e654f"

AVAILABLE_LOCALES = {
    "all": "All",
    "CN": "China",
    "EU": "Europe",
    "KR": "Koera",
    "RU": "Russia",
    "HMT": "HongKong/Macau/Taiwan",
    "US": "USA",
}

AVAILABLE_URI = {
    "CN": "https://aiot-rpc.ankasa.cn",
    "EU": "https://rpc-eu.aqara.com",
    "KR": "https://rpc-kr.aqara.com",
    "RU": "https://rpc-ru.aqara.com",
    "HMT": "https://aiot-rpc-usa.aqara.com",
    "US": "https://aiot-rpc-usa.aqara.com",
}

SUPPORTED_COMMANDS = ['control']

QUERY_VERSIONS = {
    "control": {
        2: "1.2",
        3: "1.0",
        7: "1.7"
    },
    "detail": {
        2: "6.61",
        3: "6.12",
        7: "6.12"
    }
}

class AiotCloud():
    def __init__(self, debug = False):
        self.username = ""
        self.password = ""
        self.area = ""
        self.userId = ""
        self.token = ""
        self.debug = debug
        self.uri = URI

    def encrypt_password(self, pwd: str) -> str:
        try:
            with open('lumiunited.cer', mode='rb') as f_in:
                cert = x509.load_pem_x509_certificate(f_in.read())
                public_key_obj = cert.public_key()
                public_pem = public_key_obj.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(public_pem)
                res = rsa.encrypt(md5(pwd.encode()).hexdigest().encode(), pubkey)
                res = base64.b64encode(res).decode()
                return res
        except:
            echo("encrypt password failed")
            sys.exit(-1)

    def get_headers(self, data:dict) -> dict:
        header = {
            "lang": LANG,
            "app-version": APP_VERSION,
            "phone-model": PHONE_MODEL,
            "time": str(round(time.time() * 1000)),
            "sys-type": "1",
            "nonce": NONCE_KEY,
            "area": self.area,
            "appid": APPID,
            "clientid": CLIENT_ID,
            "sign": SIGN_KEY,
            "phoneid": PHONE_ID,
            "user-agent": USER_AGENT,
            "content-type": CONTENT_TYPE
        }
        header['userId'] = self.userId
        header['token']  = self.token
        nonce = md5(str(uuid.uuid4()).encode()).hexdigest().upper()
        data_text = json.dumps(data, separators=(',', ':'))
        sign_payload  = 'Appid={}&Nonce={}&Time={}{}&{}&{}'.format(
            APPID, nonce, header['time'], "&Token=" + self.token if self.token != ' ' else '', data_text, APP_KEY)
        header['nonce'] = nonce
        header['sign']  = md5(
            sign_payload.encode().replace(b'\n', b'\\n')).hexdigest()
        return header 

    def login(self, username: str, password: str, area: str, force_login: bool = False):
        self.username = username
        self.password = password
        self.area = area
        path = "."
        currpath = pathlib.Path(__file__).parent.resolve()
        if "site-packages" in str(currpath):
            path = str(pathlib.Path.home())
        if not force_login:
            data = {}
            try:
                with open(f"{path}/aiot_login.json", mode='r') as f_in:
                    data = json.load(f_in)
            except:
                echo(f"load {path}/aiot_login.json failed")
            if username in data:
                info = data[username]
                self.userId = info.get("USERID", "")
                self.token = info.get("TOKEN", "")
            if ((len(self.userId) >= 1) and (len(self.token) >= 1)):
                return
        if "\n" in password:
            data = {"account": username, "encryptType": 2, "password": password}
        else:
            data = {"account": username, "encryptType": 2, "password": self.encrypt_password(password)}
        data_text = json.dumps(data, separators=(',',':'))
        headers = self.get_headers(data)
        headers.pop("userId")
        headers.pop("token")

        r = requests.post(f"{self.uri}/app/v1.0/lumi/user/login", data=data_text, headers = headers)
        response = r.json()

        if response["code"] == 0:
            self.userId = response['result']['userId']
            self.token = response['result']['token']
            # response['userInfo']['registerDate']
            data = {}
            try:
                with open(f"{path}/aiot_login.json", mode='r') as f_in:
                    data = json.load(f_in)
            except:
                pass

            data[username] = {
                "USERID": self.userId,
                "TOKEN": self.token
            }

            with open(f"{path}/aiot_login.json", mode='w') as f_out:
                json.dump(data, f_out)
        else:
            echo(response)
            sys.exit(-1)

    @classmethod
    def available_locales(cls) -> dict[str, str]:
        """Return available locales.

        The value is the human-readable name of the locale.
        """
        return AVAILABLE_LOCALES

    def get_devices(self, locale: Optional[str] = None):
        """Return a list of available devices keyed with a device id.

        If no locale is given, all known locales are browsed. If a device id is already
        seen in another locale, it is excluded from the results.
        """
        _LOGGER.debug("Getting devices for locale %s", locale)
        data = {}
        headers = self.get_headers(data)

        r = requests.get(f"{self.uri}/app/v1.0/lumi/app/position/device/query?size=300&startIndex=0", headers = headers)
        r.encoding = 'utf-8'

        if r.json()['code'] == 0:
            devices = r.json()['result']['devices']
            if r.json()['result']['count'] >= 300:
                r = requests.get(f"{self.uri}/app/v1.0/lumi/app/position/device/query?size=300&startIndex=1", headers = headers)
                r.encoding = 'utf-8'
                if r.json()['code'] == 0:
                    devices.append(r.json()['result']['devices'])

            new_devices = []
            for dev in devices:
                time.sleep(0.01)
                if dev['parentDeviceId']:
                    continue

                dev['ip'] = ""
                dev['mac'] = ""
                if ((dev['devicetype'] in [1, 8]) and (dev['state'] == 1)):
                    r = requests.get(f"{self.uri}/app/v1.0/lumi/app/dev/query/online?did={dev['did']}", headers = headers)
                    r.encoding = 'utf-8'
                    if r.json()['code'] == 0:
                        dev['ip'] = r.json()['result']['lanIp']
                        dev['mac'] = r.json()['result']['hwMac']
                new_devices.append(dev)

            for dev in new_devices:
                if dev['parentDeviceId']:
                    continue  # we handle children separately

                echo(f"== {dev['deviceName']} ({dev['originalName']}) ==")
                echo(f"\tModel: {dev['model']}")
                if dev.get('ip', None):
                    echo(f"\tIP: {dev['ip']} (mac: {dev['mac']})")
                echo(f"\tDID: {dev['did']}")
                echo(f"\tHomeKit: {dev['supportHomeKit']}")
                echo(f"\tVersion: {dev['firmwareVersion']}")
                childs = [x for x in devices if x['parentDeviceId'] == dev['did']]
                if childs:
                    echo("\tSub devices:")
                    for c in childs:
                        echo(f"\t\t{c['deviceName']}")
                        echo(f"\t\t\tDID: {c['did']}")
                        echo(f"\t\t\tModel: {c['model']}")


    def send(self, did: str, command: str, parameters: dict):
        """Send a command to the device.

        Basic format of the request:
        {"subjectId": lumi.123456, "data": parameters, "viewId": command, "version": "1.x"}}
        {"subjectId": lumi.123456, "data": {"restart_device": 0}}
        """
        if command not in SUPPORTED_COMMANDS:
            return {'result': f"Not supported command {command}"}
        data = {}
        headers = self.get_headers(data)
        r = requests.get(f"{self.uri}/app/v1.0/lumi/app/view/config/query?subjectId={did}&viewId={command}", headers = headers)
        r.encoding = 'utf-8'
        if r.json()['code'] != 0:
            return {'result': f"{r.json()['msgDetails']}"}

        version = r.json()['result'].get('version', None)

        data = {
            "subjectId": did,
            "data": parameters,
            "options": "",
            "viewId": command,
            "version": "1.2"
        }
        if version:
            data['version'] = version

        headers = self.get_headers(data)
        r = requests.get(
                f"{self.uri}/app/v1.0/lumi/app/view/data/query?&subjectId={did}&viewId={command}",
                data=json.dumps(data, separators=(',', ':')),
                headers = headers
            )
        r.encoding = 'utf-8'
        result = r.json()['result']
        if len(parameters.keys()) < 1:
            return {'result': "There are no parameters."}

        if r.json()['code'] == 0:
            for key in parameters.keys():
                if (result['state'] == 1):
                    datas = result['data']
                    for data_ in datas:
                        if key == data_['dataKey']:
                            if parameters[key] != data_['value']:
                                r = requests.post(
                                        f"{self.uri}/app/v1.0/lumi/app/view/write",
                                        data=json.dumps(data, separators=(',', ':')),
                                        headers = headers
                                    )
                                r.encoding = 'utf-8'
                                return r.json()
                            break
        return {'result': f"Not need to {command}."}

    def get_ota(self, did: str):
        data = {}
        headers = self.get_headers(data)

        if len(did) >= 1:
            r = requests.get(f"{self.uri}/app/v1.0/lumi/ota/query/firmware?did={did}", headers = headers)
        else:
            r = requests.get(f"{self.uri}/app/v1.0/lumi/ota/query/firmware", headers = headers)
        r.encoding = 'utf-8'
        if r.json()["code"] == 108:
            self.login(self.username, self.password, self.area, True)
            if len(did) >= 1:
                r = requests.get(f"{self.uri}/app/v1.0/lumi/ota/query/firmware?did={did}", headers = headers)
            else:
                r = requests.get(f"{self.uri}/app/v1.0/lumi/ota/query/firmware", headers = headers)
            r.encoding = 'utf-8'
        if r.json()["code"] == 0:
            echo(json.dumps(r.json()['result'], indent=2))
            #return r.json()['result']

    def fetch_info(self, did: str) -> DeviceInfo:
        devinfo: DeviceInfo = {}
        data = {}
        headers = self.get_headers(data)
        r = requests.get(f"{self.uri}/app/v1.0/lumi/app/dev/query/detail?dids=[\"{did}\"]", headers = headers)
        r.encoding = 'utf-8'

        if r.json()['code'] == 0:
            result = r.json()['result']
            devinfo['model'] = result[0]['model']
            devinfo['model_type'] = result[0]['modelType'] if result[0].get('modelType') else 0
            if result[0].get('mac'):
                devinfo['mac'] = result[0]['mac']
            if result[0].get('firmwareVersion'):
                devinfo['fw_ver'] = result[0]['firmwareVersion']

            if ((result[0]['state'] == 1) and (result[0].get('parentDeviceId', "") == "")):
                r = requests.get(f"{self.uri}/app/v1.0/lumi/app/dev/query/online?did={did}", headers = headers)
                r.encoding = 'utf-8'
                if r.json()['code'] == 0:
                    if len(r.json()['result']) >= 1:
                        devinfo['netif'] = r.json()['result']
                    if r.json()['result'].get('lanIp'):
                        devinfo['localIp'] = r.json()['result']['lanIp']

            dataKeys = {}
            model_type = devinfo['model_type']
            if ((model_type in [1, 2, 3, 7]) and (devinfo['model'] not in ['lumi.gateway.acn012'])):
                version = QUERY_VERSIONS.get("detail").get(model_type, None)
                version = version if version else "1.0"
                r = requests.get(
                        f"{self.uri}/app/v1.0/lumi/app/view/data/query?subjectId={did}&viewId=detail",
                        headers = headers
                    )
                r.encoding = 'utf-8'
                print(r.json())
                if r.json()['code'] == 0:
                    datas = r.json()['result'].get('data', [])
                    if isinstance(datas, list):
                        for d in datas:
                            if re.match("[0-9]+.[0-9]+.[0-9]+", d.get("dataKey")):
                                dataKeys.update({d.get("dataKey"): d.get("value")})

                if devinfo['model'] not in ['lumi.camera.acn003']:
                    for cmd in SUPPORTED_COMMANDS:
                        version = QUERY_VERSIONS.get(cmd).get(model_type, None)
                        version = version if version else "1.0"
                        if ((len(did) > 20) and (model_type == 3)):
                            version = "1.1"
                        r = requests.get(
                                f"{self.uri}/app/v1.0/lumi/app/view/data/query?subjectId={did}&viewId={cmd}",
                                headers = headers
                            )
                        r.encoding = 'utf-8'
                        print(r.json())
                        if r.json()['code'] == 0:
                            datas = r.json()['result'].get('data', [])
                            if isinstance(datas, list):
                                for d in datas:
                                    if (re.match("[0-9]+.[0-9]+.[0-9]+", d.get("dataKey")) or
                                            re.match("month_0_[0-9]+.[0-9]+.[0-9]+", d.get("dataKey"))
                                        ):
                                        dataKeys.update({d.get("dataKey"): d.get("value")})
                        else:
                            _LOGGER.debug(f"Query {cmd} gets response: {r.json()['msgDetails']}")
                    devinfo['res_list'] = dataKeys

        return devinfo

    def do_ota(self, did: str, ota_type: int):
        """ OTA update the device
        """
        if "ir." == did[:3]:
            return {'result': f"The {did} is not support OTA update!"}

        data = {"dids": [f"{did}"], "type": str(ota_type)}
        headers = self.get_headers(data)
        data_text = json.dumps(data, separators=(',', ':'))
        r = requests.post(f"{self.uri}/app/v1.0/lumi/ota/upgrade/firmware", data=data_text, headers = headers)
        r.encoding = 'utf-8'
        echo(r.json()['msgDetails'])
        return r.json()['result']

    def irdevice_send(self, did: str, key: str):
        """ Send the key to ir device
        """
        if "ir." != did[:3]:
            return {'result': f"The {did} is not ir device!"}

        data = {}
        headers = self.get_headers(data)
        r = requests.get(f"{self.uri}/app/v1.0/lumi/irdevice/controller/info?did={did}", headers = headers)
        r.encoding = 'utf-8'

        if ((r.json()['code'] == 0) and (r.json()['result']['type'] == 1)):
            r = requests.get(f"{self.uri}/app/v1.0/lumi/irdevice/controller/keys?did={did}", headers = headers)
            r.encoding = 'utf-8'

            _LOGGER.debug(f"The keys of ir device are:\n{r.json()['result']['keys']}")
            for k in r.json()['result']['keys']:
                if key == k['keyid']:
                    data = {"did": did, "keyId": key}
                    headers = self.get_headers(data)
                    data_text = json.dumps(data, separators=(',', ':'))
                    r = requests.post(f"{self.uri}/app/v1.0/lumi/irdevice/controller/key/click", data=data_text, headers = headers)
            return {'result': f"The {key} is not in the keys of ir device."}
        elif ((r.json()['code'] == 0) and (r.json()['result']['type'] == 2)):
            if ((len(key) >= 20) or (key[0] not in ['P', 'M', 'T', 'S'])):
                return {'result': 'The key type is wrong.'}
            data = {"did": did, "isProtocol": 0, "acKey": key}
            headers = self.get_headers(data)
            data_text = json.dumps(data, separators=(',', ':'))
            r = requests.post(f"{self.uri}/app/v1.0/lumi/irdevice/controller/key/click", data=data_text, headers = headers)
        r.encoding = 'utf-8'

        return r.json()
