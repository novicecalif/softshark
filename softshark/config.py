"""configuration file for tshark path"""
from __future__ import print_function

import os
#import iniconfig
import softshark
import sys
if sys.version_info[0] < 3:
    import ConfigParser as parser
else:
    import configparser as parser

CONFIG_PATH = os.path.join(os.path.dirname(softshark.__file__), 'config.ini')


def get_config():
    print('i am in rev 0.2.0')
    print('config path = ', CONFIG_PATH)
    #return iniconfig.IniConfig(CONFIG_PATH)
    Config = parser.ConfigParser()
    print('File about to a = %s' % CONFIG_PATH)
    Config.read(CONFIG_PATH)
    path = Config.get('tshark','tshark_path').strip()
    print('path = %s' % path)
    return path


if __name__ == '__main__':
    print(get_config())
