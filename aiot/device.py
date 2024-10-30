"""Device.

This file contains the device class.
"""
import logging
from typing import Optional

import click

try:
    from aiot.click_common import DeviceGroupMeta, LiteralParamType, command
except:
    from click_common import DeviceGroupMeta, LiteralParamType, command

try:
    from aiot.deviceinfo import DeviceInfo
except:
    from deviceinfo import DeviceInfo

try:
    from aiot.cloud import AiotCloud
except:
    from cloud import AiotCloud

_LOGGER = logging.getLogger(__name__)


class Device(metaclass=DeviceGroupMeta):
    """
    Base class for all device implementations.
    """
    retry_count = 3
    timeout = 5
    _supported_models: list[str] = []

    def __init_subclass__(cls, **kwargs):
        """Overridden to register all integrations to the factory."""
        super().__init_subclass__(**kwargs)

    def __init__(
        self,
        debug: int = 0,
        timeout: Optional[int] = None,
        *,
        model: Optional[str] = None,
    ) -> None:
        self._model: Optional[str] = model
        self._info: Optional[DeviceInfo] = None
        self._initialized: bool = False
        timeout = timeout if timeout is not None else self.timeout
        self._debug = debug

    @command(
        click.option("--username", prompt=True, required=True),
        click.option("--password", hide_input=True),
        click.option("--did", prompt=True, required=True),
        click.argument("command", type=str, required=True),
        click.argument("parameters", type=LiteralParamType(), required=False),
    )
    def raw_command(self, username, password, did, command, parameters):
        """Send a raw command to the device. This is mostly useful when trying out
        commands which are not implemented by a given device instance.

        :param str command: Command to send
        :param dict parameters: Parameters to send
        """
        if command in ['control']:
            area = "CN"
            aiot = AiotCloud()
            aiot.login(username, password, area, False)
            return aiot.send(did, command, parameters)
        return {'result': 'not support command'}

    @command(
        click.option("--username", prompt=True, required=True),
        click.option("--password", hide_input=True),
        click.option("--did", prompt=True, required=True)
    )
    def info(self, *, username, password, did, skip_cache=False) -> DeviceInfo:
        """Get Aiot protocol information from the device.

        This includes information about connected internet network and
        software versions.
        """
        if self._info is not None and not skip_cache:
            return self._info

        return self._fetch_info(username, password, did)

    def _fetch_info(self, username, password, did) -> DeviceInfo:
        """Perform aiot info query on the device the result."""
        area = "CN"
        aiot = AiotCloud()
        aiot.login(username, password, area, False)
        devinfo = aiot.fetch_info(did)
        self._info = devinfo
        _LOGGER.debug("Detected model %s", devinfo['model'])
        return devinfo

    @command(
        click.option("--username", prompt=True, required=True),
        click.option("--password", hide_input=True),
        click.option("--did", prompt=True, required=True),
        click.option("--ota_type", type=int, default=1)
    )
    def ota(self, *, username, password, did, ota_type) -> DeviceInfo:
        """ Update firmware via ota
        """
        area = "CN"
        aiot = AiotCloud()
        aiot.login(username, password, area, False)
        return aiot.do_ota(did, ota_type)