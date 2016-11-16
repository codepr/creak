# creak

Performs some of the most famous MITM attack on target addresses located in a
local network. Among these, deny navigation and download capabilities of a
target host in the local network performing an ARP poison attack and sending
reset TCP packets to every request made to the router.
Born as a didactic project for learning python language, I decline every
responsibility for any abuse, including malevolent or illegal use of this code.

## Installation

```sh
$ git clone https://github.com/codepr/creak.git
$ cd creak
$ python setup.py install
```
or simply clone the repository and run the `creak.py` after all requirements are
installed:

```sh
$ git clone https://github.com/codepr/creak.git
```

It is required to have installed `pcap` libraries for raw packet manipulations
and `dpkt` module, for dns spoofing options is required to have installed dnet
module from `libdnet` package, do not confuse it with pydnet (network
evaluation tool) module.
It can use also `scapy` if desired, can just be set in the `config` file at the
section `[output]` > `ENGINE`.

## Options

```sh
Usage: creak.py [options] dev

Options:
  -h, --help           show this help message and exit
  -1, --sessions-scan  Sessions scan mode
  -2, --dns-spoof      Dns spoofing
  -3, --session-hijack Try to steal a TCP sessions by desynchronization (old technique)
  -x, --spoof          Spoof mode, generate a fake MAC address to be used
                       during attack
  -m MACADDR           Mac address octet prefix (could be an entire MAC
                       address in the form AA:BB:CC:DD:EE:FF)
  -M MANUFACTURER      Manufacturer of the wireless device, for retrieving a
                       manufactur based prefix for MAC spoof
  -s SOURCE            Source ip address (e.g. a class C address like
                       192.168.1.150) usually the router address
  -t TARGET            Target ip address (e.g. a class C address like
                       192.168.1.150), can be specified multiple times
  -p PORT              Target port to shutdown
  -a HOST              Target host that will be redirect while navigating on
                       target machine
  -r REDIR             Target redirection that will be fetched instead of host
                       on the target machine
  -v, --verbose        Verbose output mode
  -d, --dotted         Dotted output mode
```

## Example

Most basic usage:
Deny all traffic to the target host

```sh
$ python creak.py -t 192.168.1.30 wlan0
```

Set a different gateway:

```sh
$ python creak.py -s 192.168.1.2 -t 192.168.1.30 wlan0
```

Set a different mac address for the device:

```sh
$ python creak.py -m 00:11:22:33:44:55 -t 192.168.1.30 wlan0
```

Spoof mac address generating a fake one:

```sh
$ python creak.py -x -t 192.168.1.30 wlan0
```

Spoof mac address generating one based on manufacturer(e.g Xeros):

```sh
$ python creak.py -x -M xeros -t 192.168.1.30 wlan0
```

DNS spoofing using a fake MAC address, redirecting ab.xy to cd.xz(e.g.
		localhost):

```sh
$ python creak.py -x -M xeros -t 192.168.1.30 -a www.ab.xy -r www.cd.xz wlan0
```

Deny multiple hosts in the subnet:

```sh
$ python creak.py -x -t 192.168.1.30 -t 192.168.1.31 -t 192.168.1.32 wlan0
```

## Changelog

See the [CHANGELOG](CHANGELOG.md) file.

## TODO

- Sessions grouping based on active load usage
- Complete `Scapy` support (**started**)
- Sessions hijacking (**started**)
- Port to a micro-framework wih plugin architecture (**75% completed**)

## License

See the [LICENSE](LICENSE.md) file for license rights and limitations (GNU v3).
