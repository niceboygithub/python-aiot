"""Discovery.

This file contains the method to discovery.
"""
import logging
import time
from ipaddress import ip_address
from typing import Optional

import zeroconf

try:
    from aiot.device import Device
except:
    from device import Device

_LOGGER = logging.getLogger(__name__)


class Listener(zeroconf.ServiceListener):
    """mDNS listener creating Device objects for detected devices."""

    def __init__(self):
        self.found_devices: dict[str, Device] = {}

    def create_device(self, info, addr) -> Optional[Device]:
        """Get a device instance for a mdns response."""
        name = info.name

        _LOGGER.debug("Got mdns name: %s", name)

        model, _ = name.split("_", maxsplit=1)
        model = model.replace("-", ".")
        dev = {}
        _LOGGER.info("Found a supported '%s' at %s", model, addr)
        dev[addr] = model

        return dev

    def add_service(self, zeroconf: "zeroconf.Zeroconf", type_: str, name: str) -> None:
        """Callback for discovery responses."""
        info = zeroconf.get_service_info(type_, name)
        addr = ip_address(info.addresses[0])

        if addr not in self.found_devices:
            dev = self.create_device(info, addr)
            if dev is not None:
                self.found_devices[str(addr)] = dev

    def update_service(self, zc: "zeroconf.Zeroconf", type_: str, name: str) -> None:
        """Callback for state updates."""


class Discovery:
    """mDNS discoverer for aiot based devices (_aqara-setup._tcp.local).

    Call :func:`discover_mdns` to discover devices advertising `_aqara-setup._tcp.local` on the
    local network.
    """

    @staticmethod
    def discover_mdns(*, timeout=5) -> dict[str, Device]:
        """Discover devices with mdns."""
        _LOGGER.info("Discovering devices with mDNS for %s seconds...", timeout)

        listener = Listener()
        browser = zeroconf.ServiceBrowser(
            zeroconf.Zeroconf(), "_aqara-setup._tcp.local.", listener
        )

        time.sleep(timeout)
        browser.cancel()

        return listener.found_devices