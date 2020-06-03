# -*- coding: utf-8 -*-

"""
This file contains API calls and Data
"""

import six

from sys import version_info
from termcolor import colored

from .data import *

__version__ = "1.0.0"
__all__ = ["run_console", "run", "GlobalParameters"]


# --------------------------------------------------------------------------
#
# Command line options
#
# --------------------------------------------------------------------------
def run_console(config):
    """
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    :raises: TypeError
    """
    if not isinstance(config, GlobalParameters):
        raise TypeError("Expected GlobalParameters, got '%s' instead" % type(config))

    six.print_(colored("[*]", "blue"), "Starting ScanX execution")
    run(config)
    six.print_(colored("[*]", "blue"), "Done!")


# ----------------------------------------------------------------------
#
# API call
#
# ----------------------------------------------------------------------
def run(config):
    """
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    :raises: TypeError
    """
    if not isinstance(config, GlobalParameters):
        raise TypeError("Expected GlobalParameters, got '%s' instead" % type(config))
    # --------------------------------------------------------------------------
    # Checks Python version
    # --------------------------------------------------------------------------
    # if version_info < 3:
    #     raise RuntimeError("You need Python 3.x or higher to run ScanX")
    # --------------------------------------------------------------------------
    print('----------------------------------------------------')
    from nmap import nmap
    scanner = nmap.PortScanner()
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan('127.0.0.1', '21-443')
    for host in scanner.all_hosts():
        print('Host : %s (%s)' % (host, scanner[host].hostname()))
        print('State : %s' % scanner[host].state())
        if scanner[host].has_tcp(22):
            ssh22 = 'open'
        else:
            ssh22 = 'closed'
        if scanner[host].has_tcp(23):
            telnet = 'open'
        else:
            telnet = 'closed'
        print('SSH 22 : %s' % ssh22)
        print('TELNET : %s' % telnet)
        for proto in scanner[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = scanner[host][proto].keys()
            lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
        print('Ping Scan NETWORK ...')
        scanner.scan(hosts='192.168.0.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
        hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        for host, status in hosts_list:
            print('{0}:{1}'.format(host, status))
    print('----------------------------------------------------')
    # --------------------------------------------------------------------------
