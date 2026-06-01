#!/usr/bin/env python3

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# (C) 2019 by sysmocom s.f.m.c. GmbH
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys
import time
import unittest
import socket
import subprocess
import time
import struct

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil
from osmopy.osmo_ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

TIMEOUT = 10

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assertTrue(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assertTrue(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print("Current directory: %s" % os.getcwd(), file=sys.stderr)
            print("Consider setting -b", file=sys.stderr)

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        osmoutil.end_proc(self.proc)

class TestVTYSTP(TestVTYBase):

    def vty_command(self):
        return ["./stp/osmo-stp", "-c",
                "../doc/examples/osmo-stp-multihome.cfg"]

    def vty_app(self):
        return (4239, "./stp/osmo-stp", "OsmoSTP", "stp")

    def check_sctp_sock_local(self, laddr_list, lport):
            path = "/proc/net/sctp/eps"
            try:
                with open(path, "r") as fp:
                    #drop first line, contains column names:
                    fp.readline()
                    while True:
                        # Read next line
                        line = fp.readline().strip()
                        if not line:
                            return False
                        print("%s: parsing line: %s" %(path, line))
                        it = line.split()
                        if lport == int(it[5]):
                            print("%s: local port %d found" %(path, lport))
                            itaddr_list = it[8:]
                            if len(itaddr_list) != len(laddr_list):
                                print("%s: addr list mismatch: %r vs %r" % (path, repr(itaddr_list), repr(laddr_list)))
                                continue
                            for addr in laddr_list:
                                if addr not in itaddr_list:
                                    print("%s: addr not found in list: %s vs %r" % (path, addr, repr(itaddr_list)))
                                    return False
                            return True
                    return False
            except IOError as e:
                print("I/O error({0}): {1}".format(e.errno, e.strerror))
                return False

    def testMultiHome(self):
        # first check if STP is listening in required addresses:
        found = False
        for i in range(5):
            if self.check_sctp_sock_local(['127.0.0.1', '127.0.0.2',
                                           '0000:0000:0000:0000:0000:0000:0000:0001'],
                                          2905):
                found = True
                break
            else:
                print("[%d] osmo-stp not yet available, retrying in a second" % i)
                time.sleep(1)
        self.assertTrue(found)
        try:
            proto = socket.IPPROTO_SCTP
        except AttributeError: # it seems to be not defined under python2?
            proto = 132
        # IPv4:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto)
        s.bind(('127.0.0.3', 0))
        s.settimeout(TIMEOUT)
        try:
            s.connect(('127.0.0.2',2905))
        except socket.error as msg:
            s.close()
            self.fail("Failed to connect IPv4 socket: %s" % msg)
        print("Connected to STP through SCTP (IPv4)")
        s.close()
        # IPv6:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, proto)
        s.bind(('::1', 0))
        s.settimeout(TIMEOUT)
        try:
            s.connect(('::1',2905))
        except socket.error as msg:
            s.close()
            self.fail("Failed to connect IPv6 socket: %s" % msg)
        print("Connected to STP through SCTP (IPv6)")
        s.close()

    def testTonsOfASP(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal",['']))
        self.assertTrue(self.vty.verify("cs7 instance 0",['']))
        num_of_asp = 1000
        for i in range(num_of_asp):
            asp_name = "asp-TonsofASP" + str(i)
            asp_node = "asp " + asp_name + " " + str(10000+i) + " " + "2905 m3ua"
            self.assertTrue(self.vty.verify(asp_node,['']))
            self.assertEqual(self.vty.node(), 'config-cs7-asp')
            self.assertTrue(self.vty.verify("local-ip 127.0.0.1",['']))
            self.assertTrue(self.vty.verify("local-ip ::1",['']))
            self.assertTrue(self.vty.verify("remote-ip 127.0.0.9",['']))
            self.assertTrue(self.vty.verify("remote-ip ::2",['']))
            self.assertTrue(self.vty.verify("role sg",['']))
            self.assertTrue(self.vty.verify("sctp-role server",['']))
            self.assertTrue(self.vty.verify("no shutdown",['']))
            self.assertTrue(self.vty.verify("exit",["% NOTE: Skipping automatic restart of ASP since an explicit '[no] shutdown' command was entered"]))
        as_name = "as-TonsOfASP"
        as_node = "as " + as_name + " m3ua"
        self.assertTrue(self.vty.verify(as_node,['']))
        self.assertEqual(self.vty.node(), 'config-cs7-as')
        for i in range(num_of_asp):
            asp_name = "asp-TonsofASP" + str(i)
            self.assertTrue(self.vty.verify("asp " + asp_name,['']))
        self.assertTrue(self.vty.verify("exit", ['']))

        # Now remove all of them:
        self.assertTrue(self.vty.verify(as_node,['']))
        self.assertEqual(self.vty.node(), 'config-cs7-as')
        for i in range(num_of_asp):
            asp_name="asp-TonsofASP" + str(i)
            self.assertTrue(self.vty.verify("no asp " + asp_name,['']))
        self.assertTrue(self.vty.verify("exit", ['']))
        for i in range(num_of_asp):
            asp_name="asp-TonsofASP" + str(i)
            self.assertTrue(self.vty.verify("no asp " + asp_name,['']))
        self.assertTrue(self.vty.verify("no as " + as_name,['']))

    # Validate one ASP can be configured to serve tons of AS:
    def testASPservesTonsOfAS(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal",['']))
        self.assertTrue(self.vty.verify("cs7 instance 0",['']))
        asp_name = "asp-ASPservesTonsOfAS"
        asp_node = "asp " + asp_name + " " + str(10000) + " " + "2905 m3ua"
        self.assertTrue(self.vty.verify(asp_node,['']))
        self.assertEqual(self.vty.node(), 'config-cs7-asp')
        self.assertTrue(self.vty.verify("local-ip 127.0.0.1",['']))
        self.assertTrue(self.vty.verify("local-ip ::1",['']))
        self.assertTrue(self.vty.verify("remote-ip 127.0.0.9",['']))
        self.assertTrue(self.vty.verify("remote-ip ::2",['']))
        self.assertTrue(self.vty.verify("role sg",['']))
        self.assertTrue(self.vty.verify("sctp-role server",['']))
        self.assertTrue(self.vty.verify("no shutdown",['']))
        self.assertTrue(self.vty.verify("exit",["% NOTE: Skipping automatic restart of ASP since an explicit '[no] shutdown' command was entered"]))
        num_of_as = 1000
        for i in range(num_of_as):
            as_name = "as-ASPservesTonsOfAS" + str(i)
            as_node = "as " + as_name + " m3ua"
            self.assertTrue(self.vty.verify(as_node,['']))
            self.assertEqual(self.vty.node(), 'config-cs7-as')
            self.assertTrue(self.vty.verify("asp " + asp_name,['']))
            self.assertTrue(self.vty.verify("exit", ['']))

        # Now remove all of them:
        for i in range(num_of_as):
            as_name = "as-ASPservesTonsOfAS" + str(i)
            as_node = "as " + as_name + " m3ua"
            self.assertTrue(self.vty.verify(as_node,['']))
            self.assertEqual(self.vty.node(), 'config-cs7-as')
            self.assertTrue(self.vty.verify("no asp " + asp_name,['']))
            self.assertTrue(self.vty.verify("exit", ['']))
            self.assertTrue(self.vty.verify("no as " + as_name,['']))
        self.assertTrue(self.vty.verify("no asp " + asp_name,['']))

class TestDSCP(TestVTYBase):

    def vty_command(self):
        return ["./stp/osmo-stp", "-c",
                "../doc/examples/osmo-stp.cfg"]

    def vty_app(self):
        return (4239, "./stp/osmo-stp", "OsmoSTP", "stp")

    def testDSCPSettings(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal",['']))
        self.assertTrue(self.vty.verify("cs7 instance 0",['']))
        self.assertTrue(self.vty.verify("no listen m3ua 2905",['']))
        self.assertTrue(self.vty.verify("listen m3ua 2905",['']))
        self.assertTrue(self.vty.verify("accept-asp-connections dynamic-permitted",['']))
        self.assertTrue(self.vty.verify("local-ip 127.0.0.1",['']))
        self.assertTrue(self.vty.verify("init-ip-dscp 23",['']))
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertTrue(self.vty.verify("asp asp-srv-m3ua 2906 2905 m3ua",['']))
        self.assertTrue(self.vty.verify("local-ip 127.0.0.1",['']))
        self.assertTrue(self.vty.verify("remote-ip 127.0.0.2",['']))
        self.assertTrue(self.vty.verify("ip-dscp 8",['']))
        self.assertTrue(self.vty.verify("role asp",['']))
        self.assertTrue(self.vty.verify("sctp-role server",['']))
        self.assertTrue(self.vty.verify("no shutdown",['']))
        self.assertTrue(self.vty.verify("exit",["% NOTE: Skipping automatic restart of ASP since an explicit '[no] shutdown' command was entered"]))
        self.assertTrue(self.vty.verify("asp asp-clnt-m3ua 2905 2906 m3ua",['']))
        self.assertTrue(self.vty.verify("local-ip 127.0.0.2",['']))
        self.assertTrue(self.vty.verify("remote-ip 127.0.0.1",['']))
        self.assertTrue(self.vty.verify("ip-dscp 42",['']))
        self.assertTrue(self.vty.verify("role asp",['']))
        self.assertTrue(self.vty.verify("sctp-role client",['']))
        self.assertTrue(self.vty.verify("no shutdown",['']))
        self.assertTrue(self.vty.verify("exit",["% NOTE: Skipping automatic restart of ASP since an explicit '[no] shutdown' command was entered"]))
        time.sleep(1.0)

        NETLINK_SOCK_DIAG = 4
        INET_DIAG_TOS = 5
        SOCK_DIAG_BY_FAMILY = 20
        NLM_F_REQUEST = 0x01
        NLM_F_ROOT = 0x100
        NLM_F_MATCH = 0x200
        NLM_F_DUMP = (NLM_F_ROOT | NLM_F_MATCH)
        NLMSG_HDR_SIZE = 16
        TCP_ESTABLISHED = 1
        TCP_LISTEN = 10
        NLMSG_ERROR = 2
        NLMSG_DONE = 3

        req_v2_data = struct.pack(
            "BBBBI",
            socket.AF_INET,
            socket.IPPROTO_SCTP,
            1 << (INET_DIAG_TOS - 1),
            0, # pad,
            0xFFFFFFFF,
        )
        inet_diag_sockid = struct.pack(
            "2H11I",
            0, # sport
            0, # dport
            0, 0, 0, 0, # source ip
            0, 0, 0, 0, # dest ip
            0, # idiag_if (interface index)
            0xffffffff, 0xffffffff, # idiag_cookie[2]
        )
        nl_msg_hdr = struct.pack(
            "IHHII",
            NLMSG_HDR_SIZE + len(req_v2_data) + len(inet_diag_sockid),
            SOCK_DIAG_BY_FAMILY,
            NLM_F_REQUEST | NLM_F_DUMP,
            1, # nlmsg_seq (sequence number - arbitrary)
            os.getpid()
        )
        nl_request = nl_msg_hdr + req_v2_data + inet_diag_sockid

        output = ""
        expected_output = (
            "ESTAB 127.0.0.1:2905 127.0.0.2:2906 8\n"
            "ESTAB 127.0.0.2:2906 127.0.0.1:2905 42\n"
            "LISTEN 127.0.0.1:2905 0.0.0.0:0 23\n"
            "OTHER 127.0.0.1:2905 127.0.0.2:2906 8\n"
            "OTHER 127.0.0.2:2906 127.0.0.1:2905 42"
        )

        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
        except Exception as msg:
            self.fail("Failed to open netlink socket: %s" % msg)

        try:
            sock.sendto(nl_request, (0, 0))
            sock.settimeout(5.0)

            response = sock.recv(8192)

            while len(response) >= NLMSG_HDR_SIZE:
                nl_header_len, msg_type, flags, seq, pid = struct.unpack(
                    "IHHII", response[:NLMSG_HDR_SIZE])
                if msg_type == NLMSG_ERROR:
                    error_code = struct.unpack(
                        "i", response[NLMSG_HDR_SIZE: NLMSG_HDR_SIZE+4])
                    self.fail(f"Netlink error response received. %s" % error_code)
                    break
                if msg_type == NLMSG_DONE:
                    break;
                family, state, timer, retrans = struct.unpack("4B", response[NLMSG_HDR_SIZE:NLMSG_HDR_SIZE+4])
                sport, dport, src_ip, _, _, _, dst_ip, _, _, _, ifc, c1, c2 = struct.unpack(
                    "2H11I", response[NLMSG_HDR_SIZE+4:NLMSG_HDR_SIZE+52])
                state_str = (
                   "ESTAB"
                    if state == TCP_ESTABLISHED
                    else "LISTEN" if state == TCP_LISTEN else "OTHER"
                )
                sport = socket.ntohs(sport);
                dport = socket.ntohs(dport);
                src_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", src_ip))
                dst_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", dst_ip))
                tos = 0
                rtattr_data = response[NLMSG_HDR_SIZE+72:]
                while len(rtattr_data) >= 4:
                    rta_len, rta_type = struct.unpack("HH", rtattr_data[:4])
                    if rta_len < 4 or rta_len > len(rtattr_data):
                        break
                    if rta_type == INET_DIAG_TOS:
                        tos = rtattr_data[4]
                        break
                    rtattr_data = rtattr_data[(rta_len + 3) & ~3:]

                output = output + f"{state_str} {src_ip}:{sport} {dst_ip}:{dport} {tos >> 2}\n"

                response = response[(nl_header_len + 3) & ~3:]

        except Exception as msg:
            self.fail("Failed to talk to netlink socket: %s" % msg)
        finally:
            sock.close()

        sorted_output = "\n".join(sorted(output.splitlines()))
        self.assertEqual(sorted_output, expected_output)

if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print("confpath %s, workdir %s" % (confpath, workdir))
    os.chdir(workdir)
    print("Running tests for specific VTY commands")
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVTYSTP))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestDSCP))

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
