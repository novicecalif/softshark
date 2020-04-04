""" Module used for running Tshark application."""


from __future__ import print_function
from distutils.version import LooseVersion


import os
import re
import sys
import subprocess


if sys.version_info[0] < 3 or __name__ == "__main__":
    from config import get_config
else:
    from softshark.config import get_config


def checkt():
    "simple checkit function to check."""
    return 'i am in checkt'


# Two types of exception exists.
# tshark when not found raise an exception.
class TsharkNotFoundException(Exception):
    """Tshark utility no found exception."""
    pass


# tshark version exception.
class TSharkVersionException(Exception):
    """Tshark Version compatibility exception."""
    pass


def get_process_path(tshark_path=None, process_name="tshark"):
    """Finds the path of the tshark executable.

    If the user has provided a location in config.ini would be used otherwise
    default locations would be searched.

    Args:
        tshark_path: Path of the tshark binary.
        process_name: Name of the tshark process as string.
    """
    print('I am in get_tshark_path')
    # Call the config file to see if the user specified file location
    config = get_config()
    # Declare a list of the possible paths where process exists
    # possible_paths = [config.get(process_name, "%s_path" % process_name)]
    possible_paths = [config]

    # Add the user provided path to the search list
    if tshark_path is not None:
        possible_paths.insert(0, tshark_path)

    if sys.platform.startswith("win"):
        for env in ("ProgramFiles(x86", "ProgramFiles"):
            program_files = os.getenv(env)
            if program_files is not None:
                possible_paths.append(os.path.join(program_files, "Wireshark",
                                                   "%s.exe" % process_name))
    else:
        os_path = os.getenv("PATH",
                            "/usr/bin:/usr/sbin"
                            ":/usr/lib/tshark:/usr/local/bin")
        for path in os_path.split(":"):
            possible_paths.append(os.path.join(path, process_name))

    for path in possible_paths:
        if os.path.exists(path):
            if sys.platform.startswith("win"):
                path = path.replace("\\", "/")
            print('tshark path = ', path)
            return path

    raise TsharkNotFoundException(
        "Tshark not found. Try adding its location to the configuration file."
        "Searched these paths already: {}".format(possible_paths))


def get_tshark_interfaces(tshark_path=None):
    """Returns a list of interface numbers from the output tshark -D.
    Used internally to capture on multiple interfaces.
    """
    parameters = [get_process_path(tshark_path), "-D"]
    with open(os.devnull, "w") as null:
        tshark_interfaces = subprocess.check_output(parameters,
                                                    stderr=null).decode("utf-8")
    print('raw interfaces = %s' % tshark_interfaces)
    return [line.split(".")[0] for line in tshark_interfaces.splitlines()]


def get_tshark_version(tshark_path=None):
    """ Get Tshark version."""
    parameters = [get_process_path(tshark_path), "-v"]
    with open(os.devnull, "w") as null:
        version_output = subprocess.check_output(parameters, stderr=null).decode("ascii")

    version_line = version_output.splitlines()[0]
    pattern = r'.*\s(\d+\.\d+\.\d+).*'  # match " #.#.#" version pattern
    version = re.match(pattern, version_line)
    if not version:
        raise TSharkVersionException("Unable to parse TShark version from: {}".format(version_line))
    version_string = version.groups()[0]  # Use first match found
    return LooseVersion(version_string)


def tshark_supports_duplicate_keys(tshark_version):
    """Returns boolean indicating duplicate key support."""
    return tshark_version >= LooseVersion("2.6.7")


def tshark_supports_json(tshark_version):
    """Returns boolean indicating json support."""
    return tshark_version >= LooseVersion("2.2.0")


def get_tshark_display_filter_flag(tshark_version):
    """Returns '-Y' for tshark versions >= 1.10.0 and '-R' for older versions."""
    if tshark_version >= LooseVersion("1.10.0"):
        return "-Y"
    else:
        return "-R"


if __name__ == "__main__":
    print(' I am in tshark main')
    get_process_path()
    print(get_tshark_interfaces())
    print(get_tshark_version())
    print('tshark dup support = %s' % tshark_supports_duplicate_keys('2.2.2'))
    print(tshark_supports_duplicate_keys('2.8.2'))
    print('display flag = %s' % get_tshark_display_filter_flag('1.8.0'))
    print(get_tshark_display_filter_flag('1.11.0'))
