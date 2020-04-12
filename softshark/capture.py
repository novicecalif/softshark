""" Captures the packet in various formats.

    Module has two main classes Capture and Analyze.
    Capture for capturing the packets using tshark.
    Analyze is for analyzing the already capture packet using tshark.

"""
from __future__ import print_function

# import asyncio
import json
# import os
# import threading
import subprocess
# import concurrent.futures
import sys
import logging
# from distutils.version import LooseVersion


if sys.version_info[0] < 3 or __name__ == "__main__":
    from tshark import (get_process_path, get_tshark_display_filter_flag,
                        tshark_supports_json, TSharkVersionException,
                        get_tshark_version, tshark_supports_duplicate_keys)
else:
    from softshark.tshark import (get_process_path,
                                  get_tshark_display_filter_flag,
                                  tshark_supports_json,
                                  TSharkVersionException,
                                  get_tshark_version,
                                  tshark_supports_duplicate_keys)


class TSharkCrashException(Exception):
    """ Tshark crash exception class."""
    pass


class UnknownEncyptionStandardException(Exception):
    """Unknown encryption standard class."""
    pass


class RawMustUseJsonException(Exception):
    """If the use_raw argument is True, so should the use_json argument"""
    pass


class StopCapture(Exception):
    """Exception that the user can throw anywhere in packet-handling to stop
       the capture process."""
    pass


class Capture(object):
    """Base class for packet captures.
       
       Captures provides basic functionality to capture, analyze and filter
       packets. 
       
       The capture is based on  packet count or time as shown below.
       # Example Capture based on capture time:
           c = softshark.capture.Capture(interface="en0",
                                         capture_time_seconds=10,
                                         output_file="json123.out")
           c.capture_packet()

       # Example Capture based on packet_count:
           c = softshark.capture.Capture(interface="en0",
                                         packet_count=10,
                                         output_file="json123.out")
           c.capture_packet()

       The analysis is performed on captured file as shown below.
       Example Capture based on capture time:
           c = softshark.capture.Capture(interface="en0",
                                         capture_time_seconds=10,
                                         output_file="json123.out")
           c.capture_packet()

           Once analyzed the object can be used for application as shown below:
           len(c) would indicate number of packets
           c[0] is first packet, c[1] is second packet
           for packet in pakets:
               print packets

    """
    DEFAULT_BATCH_SIZE = 2 ** 16
    SUMMARIES_BATCH_SIZE = 64
    DEFAULT_LOG_LEVEL = logging.CRITICAL
    SUPPORTED_ENCRYPTION_STANDARDS = ["wep", "wpa-pwk", "wpa-pwd", "wpa-psk"]

    def __init__(self, display_filter=None, only_summaries=False,
                 interface=None, eventloop=None, decryption_key=None,
                 encryption_type="wpa-pwd", output_file=None, decode_as=None,
                 disable_protocol=None, tshark_path=None, override_prefs=None,
                 capture_filter=None, use_json=True, include_raw=False,
                 custom_parameters=None, debug=False, monitor_mode=True,
                 packet_count=None, capture_time_seconds=None):

        self.loaded = True
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
        self._interface = interface
        self._monitor_mode = monitor_mode
        self.packet_count = packet_count
        self.capture_time_seconds = capture_time_seconds
        self.output_type = None

        if include_raw and not use_json:
            raise RawMustUseJsonException("use_json must be True if "
                                          "include_raw")

        if self.debug:
            self.set_debug()

        self.eventloop = eventloop
        if (encryption_type and encryption_type.lower() in
                self.SUPPORTED_ENCRYPTION_STANDARDS):
            self.encryption = (decryption_key, encryption_type.lower())
        else:
            error_message = ('Only the following standards are supported: %s' %
                             ", ".join(self.SUPPORTED_ENCRYPTION_STANDARDS))
            raise UnknownEncyptionStandardException(error_message)

    def __getitem__(self, item):
        """Gets the packet in the given index.
        :param item: packet index
        :return: Packet object.
        """
        return self._packets[item]

    def __len__(self):
        """Returns the length of the packets."""
        return len(self._packets)

    def next(self):
        """Returns the next packet."""
        return self.next_packet()

    # Allows for child classes to call next() from super() without 2to3
    #  "fixing" the call
    def next_packet(self):
        """Returns the next packet."""
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

    def get_parameters(self):
        """Returns the special tshark parameters to be used according to the
           configuration of this class."""
        params = []

        if self.capture_time_seconds and self.packet_count:
            raise ValueError("Specify Either packet count or capture time,"
                             "but not both")

        if self._capture_filter:
            params += ["-f", self._capture_filter]
        if self._display_filter:
            params += [get_tshark_display_filter_flag(
                           self._get_tshark_version(),), self._display_filter]
        # Raw is only enabled when JSON is also enabled.
        if self.include_raw:
            params += ["-x"]

        if self.capture_time_seconds:
            params += ["-a", "duration:%s" % self.capture_time_seconds]

        if self.packet_count:
            params += ["-c", str(self.packet_count)]

        if self._interface:
            params += ["-i", str(self._interface)]

        if self._monitor_mode:
            params += ["-I"]

        if self._custom_parameters:
            if isinstance(self._custom_parameters, list):
                params += self._custom_parameters
            elif isinstance(self._custom_parameters, dict):
                for key, val in self._custom_parameters.items():
                    params += [key, val]
            else:
                raise TypeError("Custom parameters type not supported.")

        if all(self.encryption):
            params += (["-o", "wlan.enable_decryption:TRUE", "-o",
                        'uat:80211_keys:"' + self.encryption[1] + '","' +
                        self.encryption[0] + '"'])
        if self._override_prefs:
            for preference_name, preference_value in self._override_prefs.items():
                if (all(self.encryption) and preference_name in
                        ("wlan.enable_decryption", "uat:80211_keys")):
                    # skip if override preferences also given via --encryption

                    continue
                params += ["-o", "{0}:{1}".format(preference_name,
                                                  preference_value)]

        if self._output_file:
            params += ["-w", self._output_file]

        if self._decode_as:
            for criterion, decode_as_proto in self._decode_as.items():
                params += ["-d", ",".join([criterion.strip(),
                                           decode_as_proto.strip()])]

        if self._disable_protocol:
            params += ["--disable-protocol", self._disable_protocol.strip()]

        return params

    def set_debug(self, set_to=True, log_level=logging.DEBUG):
        """Sets the capture to debug mode (or turns it off if specified)."""
        if set_to:
            handler = logging.StreamHandler(sys.stdout)
            format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            handler.setFormatter(logging.Formatter(format))
            self._log.addHandler(handler)
            self._log.level = log_level
        self.debug = set_to

    def _get_tshark_process(self):
        """Returns a new tshark process with previously-set parameters."""
        output_parameters = []
        if self.use_json:
            self.output_type = "json"
            if not tshark_supports_json(self._get_tshark_version()):
                raise TSharkVersionException("JSON only supported on"
                                             "Wireshark >= 2.2.0")
            if tshark_supports_duplicate_keys(self._get_tshark_version()):
                output_parameters.append("--no-duplicate-keys")
                self._json_has_duplicate_keys = False
        else:
            self.output_type = "psml" if self._only_summaries else "pdml"

        parameters = ([self._get_tshark_path(), "-l", "-n", "-T",
                       self.output_type] + self.get_parameters() +
                      output_parameters)
        print('parameter = ', parameters, 'type(par) = ', type(parameters))

        self._log.debug("Creating TShark subprocess with parameters: " +
                        " ".join(parameters))
        self._log.debug("Executable: %s" % parameters[0])

        tshark_process = subprocess.Popen(parameters,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          stdin=subprocess.PIPE)

        return tshark_process

    def capture_packet(self):
        """Gets the packets from the process."""
        tshark_process = self._get_tshark_process()
        print("started getting the packets ...")
        stdout, stderr = tshark_process.communicate()
        if self.output_type == "json":
            self._packets = json.loads(stdout)
        """ # Place holder to read packets as stream
         for packet in iter(lambda: tshark_process.stdout.read(), b''):
            self._packets += packet
            print("packet=",packet)
        """

    def __iter__(self):
        print('I am in iterator')
        if self.loaded:
            return iter(self._packets)
        else:
            return self._packets_from_tshark_sync()

    def __repr__(self):
        return "<%s (%d packets)>" % (self.__class__.__name__,
                                      len(self._packets))


class Analyze(Capture):
    """Gets the packets from the process.

       Packet captured already is fed as input to analyze to further analyze.

       The analysis is performed on captured file as shown below.
       Example analyze on captured file:
           packets = softshark.capture.Analyze(input_file = "kk.pcap")

           Once analyzed the object can be used for application as shown below:
           len(c) would indicate number of packets
           c[0] is first packet, c[1] is second packet
           for packet in pakets:
               print packets

    """
    def __init__(self, input_file = None, tshark_path=None):
        print("I am in Analyze")
        self.tshark_path = tshark_path
        self._current_packet = 0
        self.loaded = True
        self._log = logging.Logger(self.__class__.__name__,
                                   level=self.DEFAULT_LOG_LEVEL)
        print(self._get_tshark_path())
        parameters = [self._get_tshark_path(), "-r", input_file, "-T", "json"]
        self._log.debug("Creating TShark subprocess with parameters: " +
                        " ".join(parameters))
        self._log.debug("Executable: %s" % parameters[0])

        tshark_process = subprocess.Popen(parameters,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          stdin=subprocess.PIPE)

        stdout, stderr = tshark_process.communicate()
        self._packets = json.loads(stdout)


if __name__ == "__main__":
    capture = Analyze("kk.out")
    print('capture class has modules = % s', dir(capture))
    capture = Capture(interface="en0", packet_count=14,
                      output_file='json1.out')
    capture.capture_packet()
    print('Lenth of packets = %s' % capture.__len__())
    print(len(capture))
    # print(capture)
    for i in capture:
        print(i)
    capture.clear()
    print('Lenth of packets = %s' % capture.__len__())
