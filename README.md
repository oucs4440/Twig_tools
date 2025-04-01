# Created for a Data Communications Project
Professor: Dr. Ostermann, EECS department at Ohio University

## Project expectations:
This assignment is intended to tie together all of the concepts that we’ve discussed so far. You’re going to
build a tiny networking operating system called “twig” (like Juniper, but much, much smaller). Your Twig
operating system was a single network interface and can only respond to packets.
1. Respond to ICMP echo requests
2. Contain a simple ARP cache
3. Understand and demultiplex the UDP protocol
4. Implement a server on the UDP echo port (see RFC 862)
5. Implement a server on the UDP ”Time Protocol” port (see RFC 868)
6. IP/UDP/TCP Checksums. To be able to talk to external programs (more on that later), it will be
necessary to implement IP, ICMP, and UDP checksums
7. Hardware Addresses and ARP. For now, since we’re only responding to incoming packets, your
ARP cache will simply be populated by the mappings in incoming packets
8. Keep in mind that you will be expanding the program in a couple of weeks to support routing tables,
packet forwarding, and more advanced processing, so be sure to keep your interfaces clean and use
lots of functions that can be reused later


## Directory Tree
```bash
Twig
├── Makefile
├── README.md
├── old
│   ├── Makefile
│   ├── tcarp
│   ├── tcarp-utils.h
│   ├── tcarp.cc
│   └── tcarp.o
├── requirements.txt
├── tools
│   ├── 172.31.128.0_24.dmp
│   ├── README.md
│   ├── make_pcap.sh
│   ├── shim.py
│   ├── socket_time.c
│   └── twig_test.sh
├── twig-utils.h
├── twig.cc
└── twig_tester.sh
```
Where:
- The current working directory will be my code intended to accomplish the project.
- Tools is a list of tools provided to help work on this project.
- Old is code from previous projects relevant to this.

## Running the project
To run on the hardcoded IP (root is required):
```sh
sudo twig_tester.sh
```
This will run make on twig and run the required tools.

### twig_tester.sh
```sh
Usage: sudo ./twig_tester [-d,-td] filename
``` 
Where:
- -d is a very verbose, mostly outdated debug of all things IP and TCP.
- -td is a more accurate debug feature.

