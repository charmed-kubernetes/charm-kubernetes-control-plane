"""NOTE: Leadership data is deprecated. This is used for legacy purposes."""

from subprocess import check_call, check_output


def set(key, value):
    cmd = ["leader-set", f"{key}={value}"]
    check_call(cmd)


def get(key):
    cmd = ["leader-get", key]
    return check_output(cmd).decode()
