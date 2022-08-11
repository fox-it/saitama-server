# Saitama DNS Listener Proof-of-Concept
This is an implementation of the server-side component of the Saitama implant, to be used by detection engineers / digital defenders for research purposes. The core components that faciliate communication for the implant have been implemented. 

Some functionality (such as file download / upload or the execution of hardcoded commands) have not been implemented, but the code has been written with the possibility of future extension in mind. 

A recording of the implant's activity has been included in the data directory in two formats (pcap and zeek logs). The pcap can be replayed using replay.py

For further information regarding (the detection of) Saitama and the development of this server-side implementation, please review [our accompanying blog](https://blog.fox-it.com/2022/08/11/detecting-dns-implants-old-kitten-new-tricks-a-saitama-case-study/). 

## Usage

The implant SHA-256 hash is **e0872958b8d3824089e5e1cfab03d9d98d22b9bcb294463818d721380075a52d**. Using DotPeek or DnSpy, it should be trivial to patch the domains used for Command and Control.

### Running 'live'
Assuming you are working in a virtual environment (e.g. virtualenv or pew)

To listen on port 53, sudo privileges may be required and already running DNS listeners such as systemd-resolved may
need to be disabled.
As this is not a full-fledged interactive C2 server (nor does it aim to be), to-be executed commands have to be 
passed as parameters up front.
```
# Install requirements
pip install -r requirements.txt

# Run server
python server.py -p 53 -d -d saitama-fake-domain-one.com -d saitama-fake-domain-two.com -d saitama-fake-domain-three.com -c "whoami /priv" -c "pwd" -c "dir" -c "net user" -v
```

### Replaying a PCAP
Specify the domains used by the implant for communication, as well as the location of the PCAP file, e.g:

```
python replay.py -d saitama-fake-domain-one.com -d saitama-fake-domain-two.com -d saitama-fake-domain-three.com -f ./data/saitama.pcapng -v
```

## Repository structure:
- /data: contains recordings of saitama activity in various formats (PCAP, Zeek logs, CIM logs)
- /saitama: this folder contains scripts that implement the server-side functions that are needed to communicate with the saitama implant, schedule commands and interpret outputs.
- replay.py: Used to replay pcaps
- server.py: Used to set up a DNS server that can communicate with the implant and schedule commands

## Detection

**Suricata**:
```
alert dns $HOME_NET any -> any 53 (msg:"FOX-SRT - Trojan - Possible Saitama Exfil Pattern Observed"; flow:stateless; content:"|00 01 00 00 00 00 00 00|"; byte_test:1,>=,0x1c,0,relative; fast_pattern; byte_test:1,<=,0x1f,0,relative; dns_query; content:"."; content:"."; distance:1; content:!"."; distance:1; pcre:"/^(?=[0-9]+[a-z]|[a-z]+[0-9])[a-z0-9]{28,31}\.[^.]+\.[a-z]+$/"; threshold:type both, track by_src, count 50, seconds 3600; classtype:trojan-activity; priority:2; sid:21004170; rev:1;)
```

For further information regarding the reasoning behind this detection, see the blog associated with this repository.

**Endpoint**:

If the detection tool used allows for correlation between file modification events and the way a process spawns child processes, it is possible to do signatue-based detection of the implant when it executes a command. 

For example, in Carbon Black, such a query would be:
```
device_os:WINDOWS AND filemod_name:cnf AND ((childproc_cmdline:cmd\ \/c AND childproc_cmdline:\ exit) OR (childproc_cmdline:powershell \-exec\ bypass\ \-enc))
```

This monitors for the hardcoded 'cnf' filename that the implant uses to keep track of its state. While this detection is slightly more robust than simply monitoring for the 'Saitama.Agent' product name that the implant has, bear in mind that it is still trivial to change the 'cnf' filename used. 
