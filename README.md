
# The network interceptor
### _The one ring to rule them all..._

`network-interceptor` is a Python library that brings the Windows and Linux solutions for modifying the traffic together.

[Scapy](https://github.com/secdev/scapy) is cool, but, unfortunately, it can only sniff for packets or send its own.
But what if we want to drop or replace something?
Well, the solution depends on the platform - for some `iptables` and the `netfilterqueue` is the way to go,
for others it can be, say, `WinDivert`.
This project aims to be a helpful library for building RE tools for breaking low-level custom protocols based on TCP and UDP.

If you want some high-level protocols, like HTTP, this might not be the tool for you, go check [mitmproxy](https://github.com/mitmproxy/mitmproxy) or something.

## Features
 - All the heavy packet dissection is performed by Scapy.
 - The interface to interact with the captured packets is platform-independent!
 - Drop? Accept? Replace? Your choice!
 - A mock-like core that simply reads from a pcap/pcapng file (for testing your tools)
 - TODO: high-level TCP packet modification with seq/ack patching and fake packets...

## Installation
Right now there's no distribution available at pypi.org, so you'll have to simply
```sh
git clone https://github.com/Nemoumbra/network-interceptor.git
# (Or use the SSH one, obviously)
```
and then add it manually to your `venv` by using the standard installation routine.

For instance, `pip install /path/to/cloned/repo`. Make sure you have `setuptools` installed.

## Usage
1) Set up the interception config

```py
def prepare_config():
    config = InterceptionConfig()

    config.upd_mode = UDPMode.LowLevel
    config.tcp_mode = TCPMode.Disabled
    config.upd_action = upd_handler

    # The core arguments are used to pass some platform-dependent
    # setup info to the underlying core.
    # You can omit the cores you don't intend to use, of course...
    args = {
        "windivert": {
            "filter": "udp.DstPort == 10555"
        },
        "nfqueue": {
            "queue_num": 1  # Note: set up the iptables rules yourself
        }
    }
    config.core_arguments = args
    return config
   ```
2) Create the interceptor and run it!
```py
def main():
    config = prepare_config()
    interceptor = Interceptor(config) 
    # This will pick the interceptor implementation for your platform.

    interceptor.run()


if __name__ == "__main__":
    main()
```
The callback example:
```py
def udp_handler(packet: InterceptedPacket):
    parsed = packet.as_scapy()
    parsed[UDP].show()
    # Automatically accepts if no action is taken.
```
## Troubleshooting
### Installation
```
ERROR: Project file:</some/path>/network-interceptor has a 'pyproject.toml'and its build backend is missing the 'build_editable' hook.
```
If you see this error, your `setuptools` or `pip` need to be updated.

---
If you see an error while installing the `netfilterqueue` dependency, check *your distro's* docs
for a guide on how to install this package.
It usually requires installing a C library beforehand (it might be called `libnetfilter-queue-dev`).
---
### Usage
The crashes on startup might be caused by the fact that both `windivert` and `nfqueue` cores need admin (root) privileges.

---
If your PyCharm is struggling with the package installed as editable, try reinstalling with this command instead:
`pip install -e /path/to/cloned/repo --config-settings editable_mode=compat`.

---

## Core parameters
### `windivert`
1. `filter: str` - the filter string that will be passed to `WinDivert`.
### `nfqueue`
1. `queue_num: int` - the queue number which will be passed to `netfilterqueue`.
### `pcap`
1. `input: str` - the path to a pcap (or a pcapng) file to read the packets from
2. `output: str` - the path to a pcap file to write the resulting packet stream to. An empty string disables this feature.
## Contributing
Sure, why not? PRs are welcome.