from typing import Optional


class DeviceInfo:
    """Container of Aiot device information.

    Hardware properties such as device model, MAC address, memory information, and
    hardware and software information is contained here.
    """

    def __init__(self, data):
        """Response of a Aqara Smart Plug (Zigbee).

        {
            'deviceName': 'Smart Plug',
            'mac': '158d00039fa76d',
            'positionName': '默认房间',
            'supportMaterial': 0,
            'parentDeviceId': 'lumi1.54ef442d0232',
            'model': 'lumi.plug.v1',
            'manualUrl': '',
            'state': 1,
            'firmwareVersion': '0.0.0_0092',
            'parentModel': 'lumi.gateway.aqcn02',
            'homeId': 'real1.789615880233709568',
            'usageType': 0,
            'timeZoneId': 'Asia/Shanghai',
            'timeZone': 'GMT+08:00',
            'updateTime': 1677654443329,
            'modelType': 3,
            'connectGatewayAgreement': 1,
            'modelName': '智能插座 (国标)',
            'positionId': 'real2.789615880258875392',
            'isPreventMistakenDelete': 0,
            'parentDeviceName': '閘道器E1（青春版）o',
            'createTime': 1677654443329,
            'did': 'lumi.158d00039fa76d'
        }
        """
        self.data = data

    def __repr__(self):
        return "{} v{} ({}) @ {} - token: {}".format(
            self.model,
            self.firmware_version,
            self.mac_address,
            self.ip_address,
        )

    @property
    def network_interface(self) -> dict:
        """Information about network configuration.

        If unavailable, returns an empty dictionary.
        """
        return self.data.get("netif", {})

    @property
    def accesspoint(self):
        """Information about connected wlan accesspoint.

        If unavailable, returns an empty dictionary.
        """
        return self.data.get("ap", {})

    @property
    def model(self) -> Optional[str]:
        """Model string if available."""
        return self.data.get("model")

    @property
    def model_type(self) -> Optional[str]:
        """Model Type string if available."""
        return self.data.get("model_type")

    @property
    def firmware_version(self) -> Optional[str]:
        """Firmware version if available."""
        return self.data.get("fw_ver")

    @property
    def hardware_version(self) -> Optional[str]:
        """Hardware version if available."""
        return self.data.get("hw_ver")

    @property
    def mac_address(self) -> Optional[str]:
        """MAC address, if available."""
        return self.data.get("mac")

    @property
    def ip_address(self) -> Optional[str]:
        """IP address, if available."""
        return self.network_interface.get("localIp")

    @property
    def raw(self):
        """Raw data as returned by the device."""
        return self.data

    @property
    def __cli_output__(self):
        """Format the output for info command."""
        s = f"Model: {self.model}\n"
        s += f"Hardware version: {self.hardware_version}\n"
        s += f"Firmware version: {self.firmware_version}\n"

        return s