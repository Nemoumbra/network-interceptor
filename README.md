
# The network interceptor
### _The one ring to rule them all..._

`network-interceptor` is a Python library that brings the Windows and Linux solutions for modifying the traffic together.
The author uses this to dissect some proprietary game protocols based on TCP and UDP.

You want some high-level protocols, like HTTP?
This might not be the tool for you, go check [mitmproxy](https://github.com/mitmproxy/mitmproxy) or something.

## Features
 - All the heavy packet dissection is performed by [Scapy](https://github.com/secdev/scapy).
 - The interface to interact with the captured packets is platform-independent!
 - Drop? Accept? Replace? Your choice!
 - TODO: high-level TCP packet modification with seq/ack patching and fake packets...
 - TODO: a mock-like core that simply reads from a pcap file...

## Installation
Right now there's no distribution available at pypi.org, so you'll have to simply
```sh
git clone https://github.com/Nemoumbra/network-interceptor.git
# (Or use the SSH one, obviously)
```
and then add it manually to your `venv` by using the standard installation routine.

For instance, `pip install /path/to/cloned/repo`. Make sure you have `setuptools` installed.
Note: `pip install -e /path/to/cloned/repo --config-settings editable_mode=compat` is required for Pycharm to work properly.

## Usage
1) Set up the interception config
```py
def prepare_config():
    config = InterceptionConfig()

    config.upd_mode = UDPMode.Default
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

## Contributing
Sure, why not? PRs are welcome.