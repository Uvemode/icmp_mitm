# icmp_mitm
Small Scapy script for ICMP redirect MITM made by GiRa from the eLearnSecurity team, but with cli arguments, automated ip_forwarding/iptable rules and time delay between packets.

By default it sets the ip_forward bit and unsets it after receiving a keyboard interrupt signal, unless you had previously set it, in which case leaves it untouched.

Also sets the postrouting rule using the -S, -M and -i options. (--subnet, --mask, --interface), and deletes it after the keyboard interrupt.

There is a delay of 1s between packets, using sleep(1), feel free to adjust as you like.
