# Network Scanner

Passive network scanning tool designed to detect devices communicating with questionable foreign countries.

## Basic network topology:
                     ┌─────────────┐
                     │  Internet   │
                     └──────┬──────┘
                            │  WAN / coax
                     ┌──────┴────────────┐
                     │  Xfinity Gateway  │
                     │ router, NAT, DHCP │
                     │ (Wi-Fi disabled)  │
                     └──────┬────────────┘
                            │  LAN -> switch port 1
                     ┌──────┴───────────┐
                     │  TP-Link SG105E  │
                     │  managed switch  │
                     └───┬──────────┬───┘
                 port 2  │          │  port 5  (mirror of port 1)
              ┌──────────┴───┐   ┌──┴──────────────────────────┐
              │ Orbi mesh    │   │ Raspberry Pi - capture host │
              │ AP mode      │   │ port 5: promiscuous, no IP  │
              │ (Wi-Fi SSID) │   │ tshark -> SSD, mgmt Wi-Fi   │
              └───┬──────┬───┘   └─────────────────────────────┘
        backhaul  │      │  Wi-Fi        (passive, one-way copy)
           ┌──────┴──┐   │
           │  Orbi   │   │
           │satellite│   │
           └────┬────┘   │
          Wi-Fi │        │
              ┌─┴────────┴──────────────────┐
              │  Clients - 192.168.12.0/24  │
              │  TV, phones, laptops, IoT   │
              └─────────────────────────────┘


### How foreign IPs are identified
I got a GeoLite membership with Maxmind. They have managed database files you can grab twice weekly, which I just do manually. I'm sure there's a way for me to automate this, but I haven't gotten around to figuring that out yet. The database will allow `tshark` to identify an IP address's country of origin.

The script will then loop over a stream of packet data, and log any packets that fall under the "blacklist" of countries to a json file called the `device_naughty_list`.

The device mapping (just a json file mapping macs to device names) as well as the country blacklist (just a mapping of iso codes to the country names I want to alert on), are stored in AWS parameter store.

## Setup
To run this on your own device (presumably a Raspberry Pi), this should get you started:

1. `sudo apt install tshark`
2. I am using AWS to store the device mapping and country blacklist, but you can easily just store them locally as json config files.
3. Create a (free) GeoLite account on [Maxmind](https://www.maxmind.com/en/home). You can then download the up-to-date geo-ip databases (I use the country one, non-csv). Then store just the `.mmdb` file in `$HOME/GeoIP`
4. If you're using AWS you'll need to install `boto3`. You can either use pipenv, or any other venv manager, or just install it globally on your system. I'd recommend a virtual environment though.
5. Then just run `python app.py`. You'll want to make sure that the interface in [config.py](config.py) matches the interface of your device that will be scanning the network.