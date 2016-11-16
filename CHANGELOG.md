#### 1.0.3 - 2016-11-16

##### Added

- Scapy dns spoof method

##### Changed

- fixed minor bugs and removed `config.py` in favor of a more idiomatic
  configuration system.

#### 1.0.2 - 2016-11-01

- Evaluating the possibility of transforming `creak` in a micro-framework using
  plugin architecture in order to achieve better maintenability and extension
  capabilities, this should be easy to do in python

##### Added

- Started hijack session option, still bugged and malfunctioning

##### Changed

- Fixed some bugs and updated requirements.txt

#### 1.0.1 - 2016-10-28

##### Added

- Support for multiple host denying and spoofing, specify multiple host using
  `-t` opition

##### Changed

- Better sanitization of the input, fixed a bug regarding `input` vs `raw_input`
  misleading difference between python 2.x and python 3.x
- Fixed some bugs
- Updated TODO list

#### 1.0.0 - 2016-10-27

##### Added

- `scapy` support added
- Added a `setup.py`

##### Changed

- Full refactored the code, more maintainable, OOP for MITM side
- Fixed some bugs

#### 0.0.3 - 2016-10-26

###### Added

- `ip link` as `ifconfig` is deprecated on some distributions

###### Changed

- started porting to python 3
- fixed some minor bugs
- refactored a bit

#### 0.0.2 - 2015-09-29

###### Added

- DNS spoofing
- Manufacturer based mac spoof
- Basic scan mode for active sessions on target machine

###### Changed

- Random mac address generation
- Better arp poison system, delay added, auto `ip_forward` added

###### Fixed

- Mac address spoofing

#### 0.0.1 - 2015-09-24

###### Added

Initial release.

- MITM attack and RST injection through switched networks
- MAC address spoofing
