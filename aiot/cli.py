import logging
from typing import Any

import click

try:
    from aiot.click_common import (
        DeviceGroupMeta,
        ExceptionHandlerGroup,
        GlobalContextObject,
        json_output,
    )
except:
    from click_common import (
        DeviceGroupMeta,
        ExceptionHandlerGroup,
        GlobalContextObject,
        json_output,
    )

try:
    from aiot.cloud import AiotCloud
except:
    from cloud import AiotCloud

try:
    from aiot.discovery import Discovery
except:
    from discovery import Discovery

_LOGGER = logging.getLogger(__name__)

@click.group(cls=ExceptionHandlerGroup)
@click.option("-d", "--debug", default=False, count=True)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["default", "json", "json_pretty"]),
    default="default",
)
@click.version_option(package_name="python-aiot")
@click.pass_context
def cli(ctx, debug: int, output: str):
    logging_config: dict[str, Any] = {
        "level": logging.DEBUG if debug > 0 else logging.INFO
    }
    # The configuration should be converted to use dictConfig, but this keeps mypy happy for now
    logging.basicConfig(**logging_config)  # type: ignore
    if output in ("json", "json_pretty"):
        output_func = json_output(pretty=output == "json_pretty")
    else:
        output_func = None
    ctx.obj = GlobalContextObject(debug=debug, output=output_func)

@click.command()
@click.option("--username", prompt=True, help="The username of Aqara App")
@click.option("--password", prompt=True, hide_input=True, help="The password of Aqara App")
@click.option("--force", default=False, is_flag=True, help="Force login instand of using saving token.")
@click.pass_context
def cloud(ctx: click.Context, username, password, force):
    """Cloud commands."""

    if (not (username and password)):
        logging.error("You need to define username and password to log in")
        return False

    area = "CN"
    aiot = AiotCloud()
    aiot.login(username, password, area, force)

    aiot.get_devices(area)

@click.command()
@click.option("--username", prompt=True, help="The username of Aqara App")
@click.option("--password", prompt=True, hide_input=True, help="The password of Aqara App")
@click.option("--did", default=None, help="The did of Aqara device")
def ota_firmwares(username, password, did):
    """ Get ota firmwares."""
    area = "CN"
    aiot = AiotCloud()
    aiot.login(username, password, area, False)
    if did:
        aiot.get_ota(did)
    else:
        aiot.get_ota("")


@click.command()
@click.option("--mdns/--no-mdns", default=True, is_flag=True)
@click.option("--timeout", type=int, default=5)
def discover(mdns, timeout):
    """Discover devices using mdns methods."""
    if mdns:
        Discovery.discover_mdns(timeout=timeout)

cli.add_command(discover)
cli.add_command(cloud)
cli.add_command(ota_firmwares)


for device_class in DeviceGroupMeta._device_classes:
    cli.add_command(device_class.get_device_group())  # type: ignore[attr-defined]

def create_cli():
    return cli(auto_envvar_prefix="AIOT")


if __name__ == "__main__":
    create_cli()
