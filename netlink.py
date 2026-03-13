import hashlib
import re
from datetime import datetime, timedelta
from json import loads as json_loads
from textwrap import wrap
from subprocess import PIPE, Popen
from threading import Event
import signal

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

    @property
    def needs_config(self) -> bool:
        return self.is_established != self.is_installed

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

    def push_vxlan_configs(self, force_remove = False):
        for peer in self.all_peers.values():
            if force_remove:
                if not peer.is_installed: continue
                new_state = False
            else:
                if not peer.needs_config: continue
                new_state = peer.is_established

            with IPRoute() as ip:
                try:
                    ip.fdb(
                        "append" if new_state else "del",
                        ifindex=ip.link_lookup(ifname=self.vx_interface)[0],
                        # mac 00:00:00:00:00:00 means automatic learning
                        lladdr="00:00:00:00:00:00",
                        dst=re.sub(r"/\d+$", "", peer.lladdr),
                    )
                except NetlinkError as e:
                    print_err(f"Inserting FDB entry failed for {peer.public_key} on {self.vx_interface}.")
                    print_err(str(e))

            with IPRoute() as ip:
                try:
                    ip.route(
                        "add" if new_state else "del",
                        dst=peer.lladdr,
                        oif=ip.link_lookup(ifname=self.wg_interface)[0],
                        proto=RT_PROTO_ID,
                    )
                except NetlinkError as e:
                    print_err(f"Inserting FDB entry failed for {peer.public_key} on {self.vx_interface}.")
                    print_err(str(e))

            if new_state:
                print(f'Installed route and fdb entry for {peer.public_key} ({self.wg_interface}, {self.vx_interface})')
            else:
                print(f'Removed route and fdb entry for {peer.public_key} ({self.wg_interface}, {self.vx_interface}).')

            peer.is_installed = new_state

    def cleanup(self):
        self.push_vxlan_configs(force_remove=True)


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
            manager.push_vxlan_configs()
            if exit_event.is_set():
                break

        exit_event.wait(10)

    for manager in managers:
        manager.cleanup()
