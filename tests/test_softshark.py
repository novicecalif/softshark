#!/usr/bin/env python

"""Tests for `softshark` package."""
from __future__ import print_function

import unittest

from softshark import softshark as ss
from softshark import tshark as st
from softshark import config as sc


print('hurray sc dir = %s' % dir(sc))


class TestSoftshark(unittest.TestCase):
    """Tests for `softshark` package."""

    def setUp(self):
        """Set up test fixtures, if any."""

    def tearDown(self):
        """Tear down test fixtures, if any."""

    def test_softshark_checkit(self):
        """Test something."""
        output = ss.checkit()
        assert(output == 'i am in checkit')

    def test_tshark_checkit(self):
        output = st.checkt()
        assert(output == 'i am in checkt')

    def test_tshark_support_dupkeys(self):
        output = st.tshark_supports_duplicate_keys('2.2.2')
        assert(output == False)
        output = st.tshark_supports_duplicate_keys('2.6.7')
        assert(output == True)

    def test_tshark_support_json(self):
        output = st.tshark_supports_json('2.1.0')
        assert(output == False)
        output = st.tshark_supports_json('2.6.7')
        assert(output == True)
"""


    def test_softshark_config(self):
        output = sc.get_config()
        print(output)
        assert(output == 'C:\\Program Files\\Wireshark\\tshark.exe')

    def test_tshark_getconfig(self):
        print('tshark methods = %s' % dir(st))
        output = st.get_process_path()
        print('output to be asserted = %s' % output)
        assert(output == '/Applications/Wireshark.app/Contents/MacOS/tshark')
"""
