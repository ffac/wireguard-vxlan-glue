import errno
import hashlib
import re
from datetime import datetime, timedelta
from json import loads as json_loads
from textwrap import wrap
from subprocess import PIPE, Popen
from threading import Event
import signal
from typing import Literal

from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
import argparse
import os
import sys

import ipaddress

RT_PROTO_ID = 129
RT_PROTO = "wg-vxlan-glue"

def prefix_every_line(string, prefix):
    return prefix + prefix.join(str(string).splitlines(True))

def print_err(msg):
    SYSTEMD_JOURNAL_VERBOSITY_ERR = "<3>"
    print(prefix_every_line(msg, SYSTEMD_JOURNAL_VERBOSITY_ERR), file=sys.stderr)

exit_event = Event()


def mac2eui64(mac: str, prefix=None) -> str:
    """Converts a MAC address to an EUI64 identifier.

    If prefix is supplied, further convert the EUI64 address to an IPv6 address.
    eg:
        c4:91:0c:b2:c5:a0 -> c691:0cff:feb2:c5a0
        c4:91:0c:b2:c5:a0, FE80::/10 -> fe80::c691:cff:feb2:c5a0/10

    Arguments:
        mac: The mac address to convert.
        prefix: Prefix to use to create IPv6 address.

    Raises:
        ValueError: If mac or prefix is not correct format.

    Returns:
        An EUI64 address, or IPv6 Prefix.
    """
    # http://tools.ietf.org/html/rfc4291#section-2.5.1
    eui64 = re.sub(r"[.:-]", "", mac).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", eui64):
        raise ValueError(
            f"{mac} does not appear to be a correctly formatted mac address"
        )
    eui64 = eui64[0:6] + "fffe" + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) | 2)[2:].zfill(2) + eui64[2:]

    if not prefix:
        return ":".join(re.findall(r".{4}", eui64))
    net = ipaddress.ip_network(prefix, strict=False)
    euil = int(eui64, 16)
    return f"{net[euil]}/{net.prefixlen}"

TIMEOUT = timedelta(minutes=3)

class WireGuardPeer:

    def __init__(self, public_key: str, latest_handshake : datetime | None = None,
                 is_installed : bool = False):
        self.public_key = public_key
        self.latest_handshake = latest_handshake
        self.is_installed = is_installed

    @property
    def lladdr(self) -> str:
        m = hashlib.md5()

        m.update(self.public_key.encode("ascii"))
        hashed_key = m.hexdigest()
        hash_as_list = wrap(hashed_key, 2)
        temp_mac = ":".join(["02"] + hash_as_list[:5])

        lladdr = re.sub(pattern=r"/\d+$", repl="/128", string=mac2eui64(mac=temp_mac, prefix="fe80::/10"))
        return lladdr

    @property
    def is_established(self) -> bool:
        if not self.latest_handshake:
            return False
        return (datetime.now() - self.latest_handshake) < TIMEOUT

    """WireGuardPeer describes complete configuration for a specific WireGuard client

    Attributes:
        public_key: WireGuard Public key
        domain: Domain Name of the WireGuard peer
        lladdr: IPv6 lladdr of the WireGuard peer
        wg_interface: Name of the WireGuard interface this peer will use
        vx_interface: Name of the VXLAN interface we set a route for the lladdr to
        remove: Are we removing this peer or not?
    """

class ConfigManager:

    def __init__(self, wg_interface : str, vx_interface : str):
        self.all_peers = {}
        self.wg_interface = wg_interface
        self.vx_interface = vx_interface

    def find_by_public_key(self, public_key : str) -> list[WireGuardPeer]:
        try:
            return [self.all_peers[public_key]]
        except KeyError:
            return []

    def pull_from_wireguard(self):
        with Popen(["wg", "show", self.wg_interface, "latest-handshakes"], stdout=PIPE, text=True) as p:
            for line in p.stdout:
                (public_key, str_latest_handshake) = line.split()
                if str_latest_handshake=="0":
                    latest_handshake = 999999
                else:
                    latest_handshake = int(str_latest_handshake)
                peer = self.find_by_public_key(public_key)
                if len(peer) < 1:
                    peer = WireGuardPeer(public_key)
                    self.all_peers[public_key] = peer
                else:
                    peer = peer[0]

                peer.latest_handshake = datetime.fromtimestamp(latest_handshake)

    def remove_stale_entries(self, force_remove: bool = False):
        """
        Remove the entries of all peers which are no longer established.
        With force_remove, the entries of all installed peers are removed.

        This has to run for all managers before add_new_entries, so that a peer
        which moved to another wireguard interface has its old route removed
        before the new one is added.
        """
        remove_peers = [
            peer for peer in self.all_peers.values()
            if peer.is_installed and (force_remove or not peer.is_established)
        ]
        self._apply(remove_peers, "del")

    def add_new_entries(self):
        """
        Add the entries of all established peers which are not installed yet.
        """
        add_peers = [
            peer for peer in self.all_peers.values()
            if peer.is_established and not peer.is_installed
        ]
        self._apply(add_peers, "append")

    def cleanup(self):
        self.remove_stale_entries(force_remove=True)

    def _apply(self, peers: list[WireGuardPeer], modification: Literal["append", "del"]):
        if not peers:
            return

        with IPRoute() as ip:
            vx_index = ip.link_lookup(ifname=self.vx_interface)
            wg_index = ip.link_lookup(ifname=self.wg_interface)
            if not vx_index or not wg_index:
                print_err(f"Interface {self.vx_interface} or {self.wg_interface} not found, skipping.")
                return

            for peer in peers:
                self.modify_peer(ip, vx_index[0], wg_index[0], peer, modification)

    def modify_peer(self, ip: IPRoute, vx_index: int, wg_index: int,
                    peer: WireGuardPeer, modification: Literal["append", "del"]):
        """
        Adds or removes an FDB and iproute entry for a given wireguard peer.

        A peer is only marked as installed if both entries were added successfully,
        so that a failed installation is retried in the next round.
        Removal is best effort, the peer is always marked as not installed afterwards.
        """
        if modification == "append":
            action = "Installed"
            failed_action = "Installing"
        else:
            action = "Removed"
            failed_action = "Removing"

        success = True

        try:
            ip.fdb(
                modification,
                ifindex=vx_index,
                # mac 00:00:00:00:00:00 means automatic learning
                lladdr="00:00:00:00:00:00",
                dst=re.sub(r"/\d+$", "", peer.lladdr),
            )
        except NetlinkError as e:
            # an already existing entry is fine when retrying a partially failed install
            if not (modification == "append" and e.code == errno.EEXIST):
                success = False
                print_err(f"{failed_action} FDB entry failed for {peer.public_key} on {self.vx_interface}.")
                print_err(str(e))

        try:
            ip.route(
                # replace is idempotent, so retrying a partially failed install works
                "replace" if modification == "append" else "del",
                dst=peer.lladdr,
                oif=wg_index,
                proto=RT_PROTO_ID,
            )
        except NetlinkError as e:
            success = False
            print_err(f"{failed_action} ip route failed for {peer.public_key} on {self.wg_interface}.")
            print_err(str(e))

        if success:
            print(f'{action} route and fdb entry for {peer.public_key} ({self.wg_interface}, {self.vx_interface})')

        peer.is_installed = modification == "append" and success


def check_iface_type(iface, type):
    if not os.path.exists(f'/sys/class/net/{iface}'):
        print(f'Iface {iface} does not exist! Exiting...')
        exit(1)

    with open(f'/sys/class/net/{iface}/uevent', 'r') as f:
        for line in f.readlines():
            uevent_entries = line.replace('\n', '').split('=')
            if uevent_entries[0] == 'DEVTYPE' and uevent_entries[1] != type:
                print(f'Iface {iface} is wrong type! Should be {type}, but is {uevent_entries[1]}. Exiting...')
                exit(1)


def ensure_rt_proto_definition():
    proto_file = '/etc/iproute2/rt_protos.d/wireguard-vxlan-glue.conf'
    if os.path.isfile(proto_file):
        return

    with open(proto_file, 'w') as f:
        f.write(f'{RT_PROTO_ID}\t{RT_PROTO}\n')


def initial_cleanup():
    with IPRoute() as ip:
        res = ip.flush_routes(proto=RT_PROTO_ID)

        if len(res) > 0:
            print(f'Initial cleanup: Deleted {len(res)} route(s) with proto {RT_PROTO}.')


if __name__ == '__main__':

    class Args:
        def __init__(self):
            self.wireguard=[]
            self.vxlan=[]

    parser = argparse.ArgumentParser(description='Process some interfaces.')
    parser.add_argument('-c', '--cfg', metavar='CONFIGPATH', type=str,
                    help='ignore -w and -x and read a configfile instead')
    parser.add_argument('-w', '--wireguard', metavar='IFACE', type=str, nargs='+',
                    help='add an wireguard interfaces', default=[])
    parser.add_argument('-x', '--vxlan', metavar='IFACE', type=str, nargs='+',
                    help='add an vxlan interfaces', default=[])

    args = parser.parse_args()

    if args.cfg is not None:
        if any((args.wireguard, args.vxlan)):
            print("Please use either cfg- or 'wireguard and vxlan'-parameters, not both.")
            exit(1)
        # overwrite args
        with open(args.cfg) as configfile:
            data = configfile.read()
            configobject=json_loads(data)
            args=Args()
            args.wireguard=configobject['interfaces']['wireguard']
            args.vxlan=configobject['interfaces']['vxlan']

    if len(args.wireguard) != len(args.vxlan):
        print('Please specify equal amount of vxlan and wireguard interfaces.')
        exit(1)

    if len(args.wireguard) < 1:
        print('Please specify at least one vxlan and one wireguard interface.')
        exit(1)

    ensure_rt_proto_definition()
    initial_cleanup()

    managers = []

    for i in range(len(args.wireguard)):
        check_iface_type(args.wireguard[i], 'wireguard')
        check_iface_type(args.vxlan[i], 'vxlan')

        managers.append(ConfigManager(args.wireguard[i], args.vxlan[i]))

    def handler(signum, frame):
        if signum == signal.SIGTERM:
            print('Received SIGTERM. Exiting...')
        elif signum == signal.SIGINT:
            print('Received SIGINT. Exiting...')
        exit_event.set()

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)

    while not exit_event.is_set():
        for manager in managers:
            manager.pull_from_wireguard()
        # remove on all interfaces first, so that a peer which moved to another
        # interface does not collide with its own old entries
        for manager in managers:
            manager.remove_stale_entries()
        for manager in managers:
            manager.add_new_entries()

        exit_event.wait(10)

    for manager in managers:
        manager.cleanup()
