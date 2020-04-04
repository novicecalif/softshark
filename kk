""" Captures the packet in various formats."""
from __future__ import print_function

#import asyncio
import json
import os
import threading
import subprocess
import concurrent.futures
import sys
import logging
from distutils.version import LooseVersion

from tshark import get_process_path, get_tshark_display_filter_flag
from tshark import tshark_supports_json, TSharkVersionException, get_tshark_version, tshark_supports_duplicate_keys


class TSharkCrashException(Exception):
    pass


class UnknownEncyptionStandardException(Exception):
    pass


class RawMustUseJsonException(Exception):
    """If the use_raw argument is True, so should the use_json argument"""


class StopCapture(Exception):
    """Exception that the user can throw anywhere in packet-handling to stop the capture process."""
    pass


class Capture(object):
    """Base class for packet captures."""
    DEFAULT_BATCH_SIZE = 2**16
    SUMMARIES_BATCH_SIZE = 64
    DEFAULT_LOG_LEVEL = logging.CRITICAL
    SUPPORTED_ENCRYPTION_STANDARDS = ["wep", "wpa-pwk", "wpa-pwd", "wpa-psk"]

    def __init__(self,
                 display_filter=None,
                 only_summaries=False,
                 eventloop=None,
                 decryption_key=None,
                 encryption_type="wpa-pwd",
                 output_file=None,
                 decode_as=None,
                 disable_protocol=None,
                 tshark_path=None,
                 override_prefs=None,
                 capture_filter=None,
                 use_json=True,
                 include_raw=False,
                 custom_parameters=None,
                 debug=False):

        self.loaded = False
        self.tshark_path = tshark_path
        self._override_prefs = override_prefs
        self.debug = debug
        self.use_json = use_json
        self.include_raw = include_raw
        self._packets = []
        self._current_packet = 0
        self._display_filter = display_filter
        self._capture_filter = capture_filter
        self._only_summaries = only_summaries
        self._output_file = output_file
        self._running_processes = set()
        self._decode_as = decode_as
        self._disable_protocol = disable_protocol
        self._json_has_duplicate_keys = True
        self._log = logging.Logger(self.__class__.__name__,
                                   level=self.DEFAULT_LOG_LEVEL)
        self._closed = False
        self._custom_parameters = custom_parameters
        self.__tshark_version = None

        if include_raw and not use_json:
            raise RawMustUseJsonException(
                "use_json must be True if include_raw")

        if self.debug:
            self.set_debug()

        self.eventloop = eventloop
        if encryption_type and encryption_type.lower(
        ) in self.SUPPORTED_ENCRYPTION_STANDARDS:
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            raise UnknownEncyptionStandardException(
                "Only the following standards are supported: %s." %
                ", ".join(self.SUPPORTED_ENCRYPTION_STANDARDS))

    def __getitem__(self, item):
        """Gets the packet in the given index.
        :param item: packet index
        :return: Packet object.
        """
        return self._packets[item]

    def __len__(self):
        return len(self._packets)

    def next(self):
        return self.next_packet()

    # Allows for child classes to call next() from super() without 2to3 "fixing"
    # the call
    def next_packet(self):
        if self._current_packet >= len(self._packets):
            raise StopIteration()
        cur_packet = self._packets[self._current_packet]
        self._current_packet += 1
        return cur_packet

    def clear(self):
        """Empties the capture of any saved packets."""
        self._packets = []
        self._current_packet = 0

    def reset(self):
        """Starts iterating packets from the first one."""
        self._current_packet = 0

    def _get_tshark_path(self):
        return get_process_path(self.tshark_path)

    def _stderr_output(self):
        # Ignore stderr output unless in debug mode (sent to console)
        return None if self.debug else subprocess.DEVNULL

    def _get_tshark_version(self):
        if self.__tshark_version is None:
            self.__tshark_version = get_tshark_version(self.tshark_path)
        return self.__tshark_version

    def get_parameters(self, packet_count=None):
        """Returns the special tshark parameters to be used according to the configuration of this class."""
        params = []
        if self._capture_filter:
            params += ["-f", self._capture_filter]
        if self._display_filter:
            params += [
                get_tshark_display_filter_flag(self._get_tshark_version(), ),
                self._display_filter
            ]
        # Raw is only enabled when JSON is also enabled.
        if self.include_raw:
            params += ["-x"]
        if packet_count:
            params += ["-c", str(packet_count)]

        if self._custom_parameters:
            if isinstance(self._custom_parameters, list):
                params += self._custom_parameters
            elif isinstance(self._custom_parameters, dict):
                for key, val in self._custom_parameters.items():
                    params += [key, val]
            else:
                raise TypeError("Custom parameters type not supported.")

        if all(self.encryption):
            params += [
                "-o", "wlan.enable_decryption:TRUE", "-o", 'uat:80211_keys:"' +
                self.encryption[1] + '","' + self.encryption[0] + '"'
            ]
        if self._override_prefs:
            for preference_name, preference_value in self._override_prefs.items(
            ):
                if all(self.encryption) and preference_name in (
                        "wlan.enable_decryption", "uat:80211_keys"):
                    continue  # skip if override preferences also given via --encryption options
                params += [
                    "-o", "{0}:{1}".format(preference_name, preference_value)
                ]

        if self._output_file:
            params += ["-w", self._output_file]

        if self._decode_as:
            for criterion, decode_as_proto in self._decode_as.items():
                params += [
                    "-d",
                    ",".join([criterion.strip(),
                              decode_as_proto.strip()])
                ]

        if self._disable_protocol:
            params += ["--disable-protocol", self._disable_protocol.strip()]

        return params

    def _get_tshark_process(self, packet_count=None, stdin=None):
        """Returns a new tshark process with previously-set parameters."""
        output_parameters = []
        if self.use_json:
            output_type = "json"
            if not tshark_supports_json(self._get_tshark_version()):
                raise TSharkVersionException(
                    "JSON only supported on Wireshark >= 2.2.0")
            if tshark_supports_duplicate_keys(self._get_tshark_version()):
                output_parameters.append("--no-duplicate-keys")
                self._json_has_duplicate_keys = False
        else:
            output_type = "psml" if self._only_summaries else "pdml"

        parameters = ([
            self._get_tshark_path(), "-i", "en0", "-c", "2", "-w", "pk", "-I",
            "-l", "-n", "-T", output_type
        ] + self.get_parameters(packet_count=packet_count) + output_parameters)
        print('parameter = ', parameters, 'type(par) = ', type(parameters))

        self._log.debug("Creating TShark subprocess with parameters: " +
                        " ".join(parameters))
        self._log.debug("Executable: %s" % parameters[0])

        proc = subprocess.Popen(parameters,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        #output = subprocess.check_output(parameters)
        #print(output)
        print('\n\noutput type = \n\n', type(proc.stdout))
        """
        for line in proc.stdout:
            print(line, end="" )
        """

        # stdout, stderr
        jsonS, stderr = proc.communicate()
        d = json.loads(jsonS)
        print(d[0])
        print('\n\n stderr = %s' % stderr)

        with open('json.out', 'w') as f:
            json.dump(d, f)
        #return tshark_process

    def __iter__(self):
        if self.loaded:
            return iter(self._packets)
        else:
            return self._packets_from_tshark_sync()

    def __repr__(self):
        return "<%s (%d packets)>" % (self.__class__.__name__,
                                      len(self._packets))


if __name__ == "__main__":
    c = Capture(output_file='json1.out')
    c._get_tshark_process()
