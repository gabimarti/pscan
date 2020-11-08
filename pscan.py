#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# -----------------------------------------------------------------------------------------------------------
# Name:             pscan.py
# Purpose:          Python Multithread Network Scanner
#                   Search for open ports in a network range.
#                   Based on the demonseye-net-search.py module from my "Demons eye keylogger" keylogger poc
#                   https://github.com/gabimarti/Demons-eye-keylogger
#                   a small server can be activated to receive the keys.
#
# Author:           Gabriel Marti Fuentes
# email:            gabimarti at gmail dot com
# GitHub:           https://github.com/gabimarti
# Created:          20/08/2020
# License:          GPLv3
# Version:          0.1.1
# -----------------------------------------------------------------------------------------------------------


import argparse
import base64
import ipaddress
import logging
import socket
import sys
import textwrap
import threading
import time
import urllib.request
from urllib.error import HTTPError, URLError


########################################################
# CONSTANTS
########################################################

BANNER = """ 
 ______   ______                   
(_____ \ / _____)                  
 _____) | (____   ____ _____ ____  
|  ____/ \____ \ / ___|____ |  _ \ 
| |      _____) | (___/ ___ | | | |
|_|     (______/ \____)_____|_| |_| """
APPNAME = 'Python Multithread Network Scanner'      # Just a name
VERSION = 'v0.1.1'                                  # Version
SERVER_ACCEPT_TIMEOUT = 0.1
PORT_LIST_SCAN = [21, 22, 25, 80, 110, 3389, 9100]  # Default list of ports to Scan. For testing multiple ports
BUFFER_SIZE = 4096                                  # Buffer size
DEFAULT_TIMEOUT = 2                                 # Default Timeout (seconds)
DEFAULT_WAIT_RESPONSE = False                       # Wait response after sending message
ENCODING = 'utf-8'                                  # Encoding for message sended
LOGGING_LEVEL = logging.DEBUG                       # Log level. Can be -> DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILENAME = 'pscan.log'                          # File name for the Log Level registered data
DEFAULT_DELAY_BIP = 20                              # Default delay in ms between IP, 20ms
DEFAULT_DELAY_BPO = 5                               # Default delay in ms between PORTS, 5ms
MAX_THREADS = 16384                                 # Maximum simultaneous threads
TIME_SLEEP_THREAD = 0.1                             # Pause to avoid thread oversaturation

########################################################
# VARIABLES
########################################################
threadList = []                                     # List of active threads
net_range = ''                                      # Network Range to scan, if not provided, it detects itself
port_list = []                                      # Port list for command line test
timeout = DEFAULT_TIMEOUT                           # Timeout on port connection
total_threads_launched = 0                          # Total threads launched
total_current_threads_running = 0                   # Total threads running at one moment
max_concurrent_threads = 0                          # Store max concurrent threads


########################################################
# CLASSES
########################################################

# Scan a host (ip), for open ports in port_list.
class HostScan(threading.Thread):
    def __init__(self, ip, port_list, message, timeout, waitresponse, delayport, maxthreads):
        threading.Thread.__init__(self)
        self.open_ports = []
        self.ports = port_list                              # All ports can be self.ports = range(1, 0xffff + 1)
        self.ip = ip                                        # ip to scan
        self.message = message                              # message to send
        self.threads = []                                   # Thread list
        self.timeout = timeout                              # Timeout - alternative: socket.setdefaulttimeout(timeout)
        self.wait = waitresponse                            # wait response after send message
        self.delayport = delayport                          # delay between port scan in milliseconds
        self.maxthreads = maxthreads                        # maximum simultaneous concurrent threads
        self.lock = threading.Lock()                        # thread lock

    def scan(self, host, port):
        global total_threads_launched, total_current_threads_running, max_concurrent_threads

        # Increment running threads counter and max concurrent threads
        self.lock.acquire()
        total_threads_launched += 1
        total_current_threads_running += 1
        if total_current_threads_running > max_concurrent_threads:
            max_concurrent_threads = total_current_threads_running
        self.lock.release()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       # ipv4 (AF_INET) tcp (SOCK_STREAM)
            s.settimeout(self.timeout)                                  # Sets timeout
            s.connect((host, port))
            try:
                if len(str(self.message)) > 0:
                    logging.debug('Sending message {} to {}:{} '.format(self.message, host, port))
                    s.send(self.message.encode(ENCODING))
                    if self.wait:
                        response = s.recv(BUFFER_SIZE).decode(ENCODING)
                        # Decode if Base64
                        try:
                            response = str(base64.b64decode(response), ENCODING)
                        except Exception as e:
                            logging.error('Error decoding Base64 : {}'.format(e))
                    else:
                        response = ''
                else:
                    response = ''
            except Exception as e:
                response = ''               # No response
                logging.debug('No response : %s ' % e)
            finally:
                if (self.wait and response != '') or not self.wait:
                    self.open_ports.append('Host {} Port {} [Open] {}'.format(host, port, response))
        except Exception as e:
            logging.error('Host {} Port {} Exception {} '.format(host, port, e))
            pass
        finally:
            s.close()

        # Decrement running threads counter
        self.lock.acquire()
        total_current_threads_running -= 1
        self.lock.release()

    def write(self):
        for op in self.open_ports:
            print(op)
            logging.info(op)

    def run(self):
        self.threads = []
        logging.info('Start scan ' + str(self.ip))
        # Enumerate ports list and scan and add to thread
        for i, port in enumerate(self.ports):
            s = threading.Thread(target=self.scan, args=(self.ip, port))
            s.start()
            self.threads.append(s)
            time.sleep(self.delayport/1000)
            # Prevent thread oversaturation
            wait = True
            while wait:
                self.lock.acquire()
                if total_current_threads_running < self.maxthreads:
                    self.lock.release()
                    wait = False
                else:
                    self.lock.release()
                    time.sleep(TIME_SLEEP_THREAD)

        # Finish threads before main thread starts again
        for thread in self.threads:
            thread.join()

        # Write out the ports that are open
        self.write()


# Scan a range of IPs for open ports
# Get CIDR net_gange, List of port_list, message to send, verbosity
class RangeScan(threading.Thread):
    def __init__(self, net_range, port_list, message, timeout, waitresponse, delayip, delayport, maxthreads):
        threading.Thread.__init__(self)
        self.active_hosts = []                                      # IP Host list with at least one open port
        self.ip_net = ipaddress.ip_network(net_range)               # Create the network
        self.all_hosts = list(self.ip_net.hosts())                  # Generate all hosts in network
        self.port_list = port_list                                  # List of ports to scan
        self.message = message                                      # Message to send
        self.threads = []                                           # Thread list
        self.own_host = socket.gethostname()                        # Client Host name
        self.own_ip = socket.gethostbyname(self.own_host)           # Client Host ip
        self.timeout = timeout                                      # Timeout
        self.wait = waitresponse
        self.delayip = delayip
        self.delayport = delayport
        self.maxthreads = maxthreads
        self.hosts_scanned = 0                                      # Total hosts scanned

    def start(self):
        logging.debug('This host is %s (%s) ' % (self.own_host, self.own_ip))

        self.hosts_scanned = 0
        for ip in self.all_hosts:                                   # Scan the network range
            # Thread host port scan
            hs = HostScan(str(ip), self.port_list, self.message, self.timeout, self.wait, self.delayport,
                          self.maxthreads)
            hs.start()
            self.threads.append(hs)
            self.hosts_scanned += 1
            time.sleep(self.delayip/1000)

        # Wait to finish threads before main thread starts again
        for thread in self.threads:
            thread.join()


########################################################
# FUNCTIONS
########################################################

# Get the external ip
# Alternate services
#   https://ipinfo.io/ip
#   http://ifconfig.me/ip
def get_external_ip():
    try:
        external_ip = urllib.request.urlopen('https://ident.me').read().decode(ENCODING)
    except (HTTPError, URLError) as error:
        pass                                # future use
    except timeout:
        # if first server fails, try another url
        try:
            external_ip = urllib.request.urlopen('https://ipinfo.io/ip').read().decode(ENCODING)
        except (HTTPError, URLError) as error:
            pass                            # future use
        except timeout:
            return ''
        else:
            return external_ip
    else:
        return external_ip


# Convert an ip to a CIDR / 24 range
def ip_to_cidr24(ip_to_convert):
    blist = ip_to_convert.split('.')        # split bytes
    blist[3] = '0'                          # changes last byte
    cidr = '.'
    cidr = cidr.join(blist)                 # collect the bytes again
    cidr += '/24'                           # adds mask
    return cidr


# Return Logging Level
def set_logging_level(verbose_level):
    switcher = {
        0:  sys.maxsize,                # No logging, no print
        1:  logging.CRITICAL,
        2:  logging.ERROR,
        3:  logging.WARNING,
        4:  logging.INFO,
        5:  logging.DEBUG
    }
    return switcher.get(verbose_level, sys.maxsize)


# Parse command line parameters
def parse_params():
    parser = argparse.ArgumentParser(description=APPNAME + ' ' + VERSION,
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     epilog='Simple scanning of specific ports in a network range.')
    parser.add_argument('-r', '--range', type=str, default="",
                        help='Specify the network range in CIDR format. ' +
                             'If not provided, an attempt is made to autodetect a local class C range. ' +
                             'Example: 192.168.1.0/24')
    parser.add_argument('-w', '--wanauto', action='store_true', default=False,
                        help='If this option is set (and no -r has been specified), ' +
                             'an automatic class C range will be set for the current Wan IP.')
    parser.add_argument('-p', '--ports', type=int, nargs='+', default=list(PORT_LIST_SCAN),
                        help='Specify a list of ports to scan. Default value: ' + str(PORT_LIST_SCAN))
    parser.add_argument('-m', '--message', type=str, default='',
                        help='Message to send to host. If empty (-m \'\'), then not message is sent.')
    parser.add_argument('-e', '--waitresponse', action='store_true', default=DEFAULT_WAIT_RESPONSE,
                        help='Wait response from host after sending Message (if sent). ' +
                             'If this is enable then only ports with response are shown ' +
                             'Default value: ' + str(DEFAULT_WAIT_RESPONSE))
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Timeout in seconds on port connection. Default value: ' + str(DEFAULT_TIMEOUT))
    parser.add_argument('-i', '--delaybetweenip', type=int, default=DEFAULT_DELAY_BIP,
                        help='Delay in milliseconds (enter integer) between IP threads. Default value: ' +
                             str(DEFAULT_DELAY_BIP))
    parser.add_argument('-o', '--delaybetweenport', type=int, default=DEFAULT_DELAY_BPO,
                        help='Delay in milliseconds (enter integer) between PORT threads. Default value: ' +
                             str(DEFAULT_DELAY_BPO))
    parser.add_argument('-d', '--maxthreads', type=int, default=MAX_THREADS,
                        help='Maximum number of simultaneous threads. Default value: ' + str(MAX_THREADS))
    parser.add_argument('-v', '--verbose', type=int, choices=[0, 1, 2, 3, 4, 5], default=0,
                        help=textwrap.dedent('Debug verbose to console when testing. \n' 
                            'Default value: 0 \n'
                            ' 0 = No verbose \n'  
                            ' 1 = CRITICAL \n'  
                            ' 2 = ERROR \n'
                            ' 3 = WARNING \n' 
                            ' 4 = INFO \n'
                            ' 5 = DEBUG '))
    parser.add_argument('-l', '--logtofile', action='store_true', required=False, default=False,
                        help='If set, log messages are saved in a file named {} instead of on screen.'.
                        format(LOG_FILENAME))
    args = parser.parse_args()
    return args


def main():
    global listen_server_instance, listen_server_enabled

    # Check and parse parameters
    args = parse_params()
    net_range = args.range

    # Sets logging settings
    log_format = '%(asctime)s %(levelname)08s: L%(lineno)4s %(funcName)25s(): %(message)s'
    log_date_fmt = '%d/%m/%Y %I:%M:%S %p'

    if args.logtofile:
        log_handlers = [logging.FileHandler(LOG_FILENAME)]      # If set Log to File (-f)
    else:
        log_handlers = [logging.StreamHandler()]                # Default Log handler console

    logging.basicConfig(level=set_logging_level(args.verbose), format=log_format, datefmt=log_date_fmt,
                        handlers=log_handlers)

    # Host info
    hostname = socket.gethostname()
    localip = socket.gethostbyname(hostname)
    externalip = get_external_ip()

    print(BANNER)
    print(APPNAME + ' ' + VERSION)
    print('==============================================')

    if net_range == "" and not args.wanauto:
        net_range = ip_to_cidr24(localip)
        print('Network range to scan (local autodetect) ' + net_range)
    elif net_range == "" and args.wanauto:
        net_range = ip_to_cidr24(externalip)
        print('Network range to scan (wan autodetect) ' + net_range)
    else:
        print('Network range to scan ' + net_range)

    print('Ports list ' + str(args.ports))
    print('Message to send \'' + args.message + '\'')
    print('Wait response after send message ' + str(args.waitresponse))
    print('Timeout {} seconds, Delay IP {}ms, Delay PORT {}ms, Maxthreads {} ' .
          format(args.timeout, args.delaybetweenip, args.delaybetweenport, args.maxthreads))

    print('---')
    print('This Host {} : IP local {} : IP wan {} '.format(hostname, localip, externalip))

    logging.debug('Command Line settings: Verbose: {} | Log to File: {} | Net Range {} | Port List {} ' .
                  format(args.verbose, args.logtofile, args.range, args.ports ))

    print('Scanning ...')
    start = time.perf_counter()
    scanner = RangeScan(net_range, args.ports, args.message, args.timeout, args.waitresponse, args.delaybetweenip,
                        args.delaybetweenport, args.maxthreads)
    scanner.start()
    total_hosts = scanner.hosts_scanned
    total_time = time.perf_counter() - start
    msg = 'Scanned {} hosts at {} in {:.2f} seconds '.format(total_hosts, args.range, total_time)
    print(msg)
    logging.info(msg)
    msg = 'Total {} threads launched, and max simultaneous was {} threads'.format(total_threads_launched,
                                                                                  max_concurrent_threads)
    print(msg)
    logging.info(msg)
    if total_current_threads_running > 0:
        msg = 'Something strange happens because the threads running is {} '.format(total_current_threads_running)
        print(msg)
        logging.critical(msg)

    logging.shutdown()

if __name__ == '__main__':
    main()

