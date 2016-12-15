# creak

Basic plugin-defined architecture to automate some MITM attacks on a LAN
context, with support for easy addition of new plugin or extension of the
current ones. Among these, poison, spoofing and deny navigation and download
capabilities of a target host in the local network performing an ARP poison
attack and sending reset TCP packets to every request made to the router.
Born as a didactic project for learning python language, I decline every
responsibility for any abuse or illegal uses.

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
module from `libdnet` package, do not confuse it with pydnet (network evaluation
tool) module.
It can use also `scapy` if desired, can just be set in the `config.py` file.

## Options

```sh
Usage: creak.py [options] dev

Options:
  -h, --help           show this help message and exit
  -1, --sessions-scan  Sessions scan mode
  -2, --dns-spoof      Dns spoofing
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

## Changelog

See the [CHANGELOG](CHANGELOG.md) file.

## TODO

- Parametrized run
- Complete `Scapy` support

## License

See the [LICENSE](LICENSE.md) file for license rights and limitations (GNU v3).
