"""Exception.

This file contains exceptions class.
"""
class DeviceException(Exception):
    """Exception wrapping any communication errors with the device."""

class DeviceError(DeviceException):
    """Exception communicating an error delivered by the target device.

    The device given error code and message can be accessed with  `code` and `message`
    variables.
    """

    def __init__(self, error):
        self.code = error.get("code")
        self.message = error.get("message")
