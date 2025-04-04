import os
from pathlib import Path
from subprocess import check_call
from typing import Optional, TypedDict

DEFAULT_TIMEOUT = 300  # 5 minutes
CHARM_DIR = Path(os.environ.get("JUJU_CHARM_DIR") or Path(__file__).parent.parent)
ROUTABLED_SH = (CHARM_DIR / "templates/routabled.sh.tmpl").read_text()
ROUTABLED_PATH = Path("/etc/networkd-dispatcher/routable.d/")


class EventConfig(TypedDict):
    """Configuration used by service and timer templates.

    Attributes:
        app: Name of the juju application.
        event: Name of the event.
        timeout: Seconds before the event handle is timeout.
        unit_num: Number of the juju unit.
    """

    app: str
    event: str
    timeout: int
    unit_num: int


def ensure(event_name: str, timeout: Optional[int] = None) -> None:
    """Ensure that a routeabled script and timer are registered to dispatch the given event.

    The timeout is the number of seconds before an event is timed out. If not set or 0,
    it defaults to 5m

    Args:
        event_name: Name of the juju event to schedule.
        interval: Number of seconds between emitting each event.
        timeout: Timeout for each event handle in seconds.

    Raises:
        TimerEnableError: Timer cannot be started. Events will be not emitted.
    """
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    unit_name = os.environ["JUJU_UNIT_NAME"]
    app, unit_num = unit_name.split("/")

    context: EventConfig = {
        "app": app,
        "event": event_name,
        "timeout": timeout,
        "unit_num": unit_num,
    }
    _render_routabled(event_name, context)


def _render_routabled(event_name: str, context: EventConfig) -> None:
    """Write event configuration files to routabled path.

    Args:
        template_type: Name of the template type to use. Can be 'service' or 'timer'.
        event_name: Name of the event to schedule.
        context: Addition configuration for the event to schedule.
    """
    ROUTABLED_PATH.mkdir(parents=True, exist_ok=True)
    dest = ROUTABLED_PATH / f"{context['app']}.{event_name}.sh"
    content = ROUTABLED_SH.format(**context)
    if not dest.exists() or dest.read_text() != content:
        dest.write_text(ROUTABLED_SH.format(**context))
        dest.chmod(0o755)

        check_call(["systemctl", "enable", "--now", "systemd-networkd"])
        check_call(["systemctl", "restart", "networkd-dispatcher"])
