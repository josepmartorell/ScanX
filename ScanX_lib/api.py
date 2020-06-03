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
    from nmap import nmap
    scanner = nmap.PortScanner()
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan('127.0.0.1', '21-443')
    for host in scanner.all_hosts():
        print('----------------------------------------------------')
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

    print('----------------------------------------------------')
    # --------------------------------------------------------------------------
