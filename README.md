# creak

Basic plugin-defined architecture to automate some MITM attacks on a LAN
context, with support for easy addition of new plugin or extension of the
current ones. Among these, poison, spoofing and deny navigation and download
capabilities of a target host in the local network performing an ARP poison
attack and sending reset TCP packets to every request made to the router.
Born as a didactic project for learning python language, I decline every
responsibility for any abuse or illegal uses.

[![demo](https://asciinema.org/a/10eyg4vz9hmisqz5xaz51opzy)](https://asciinema.org/a/10eyg4vz9hmisqz5xaz51opzy?autoplay=1)

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

## Extending

To add a plugin to the framework it is required to just extend base class `baseplugin.py` and define
the method `run` according to the parameters needed, and the informations of the
plugin in the `init_plugin` method, including the privilege level needed.

### Example - greeter.py

```python
# greeter plugin sample

from creak.baseplugin import BasePlugin

class Plugin(BasePlugin):

    """ A plugin that doesn't do much, hust greet the user """

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Greets the user')
        self._set_required_params(name=False)

    def run(self, kwargs):
        """ I don't do a lot """
        if 'name' not in kwargs:
            kwargs['name'] = 'stranger'
        print("Hello %s" % kwargs['name'])
```

## Changelog

See the [CHANGELOG](CHANGELOG.md) file.

## TODO

- Parametrized run
- Complete `Scapy` support

## License

See the [LICENSE](LICENSE.md) file for license rights and limitations (GNU v3).
