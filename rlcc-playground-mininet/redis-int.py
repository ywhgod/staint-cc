#!/usr/bin/env python3
import sys
import redis  # Import redis library

from scapy.all import (
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    PacketListField,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    """Find the interface to sniff packets from."""
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "s1-eth2" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


class SwitchTrace(Packet):
    """Represents the SwitchTrace structure."""
    fields_desc = [
        IntField("swid", 0),    # Switch ID
        IntField("qdepth", 0),  # Queue depth
        IntField("delay", 0)    # Processing delay
    ]

    def extract_padding(self, p):
        return "", p


class IPOption_MRI(IPOption):
    """Represents the MRI (Measurement and Reporting Information) IP option."""
    name = "MRI"
    option = 31  # Option type for MRI
    fields_desc = [
        _IPOption_HDR,
        FieldLenField(
            "length", None, fmt="B",
            length_of="swtraces", adjust=lambda pkt, l: l * 12 + 4  # Adjust for updated structure
        ),
        ShortField("count", 0),  # Number of SwitchTrace entries
        PacketListField(
            "swtraces", [], SwitchTrace,
            count_from=lambda pkt: pkt.count  # Parse 'count' SwitchTrace entries
        )
    ]


def handle_pkt(pkt):
    """Handle each captured packet."""
    print("got a packet")
    #pkt.show2()  # Show parsed packet with all layers

    # Extract the SwitchTrace information
    if pkt.haslayer(IPOption_MRI):
        mri_option = pkt.getlayer(IPOption_MRI)
        for swtrace in mri_option.swtraces:
            swid = swtrace.swid
            qdepth = swtrace.qdepth
            delay = swtrace.delay

            # Publish the values to Redis in the INT channel
            publish_to_redis('1001' , swid, qdepth, delay)

    sys.stdout.flush()


def publish_to_redis(rlcc_flag, swid, qdepth, delay):
    """Publish the extracted values to the Redis INT channel."""
    # Connect to Redis
    redis_host = "10.0.3.3"  # Change to your Redis server address
    redis_port = 6379         # Default Redis port
    r = redis.StrictRedis(host=redis_host, port=redis_port, db=0)

    # Prepare the message
    message = f"{swid};{qdepth};{delay}"
    # Publish the message to the INT channel
    r.publish(f"rlccint_{rlcc_flag}", str(message))
    print(f"Published to Redis INT channel: {message}")


def main():
    """Main function to sniff packets on eth0."""
    iface = get_if()  # Get interface
    print(f"Sniffing on {iface}")
    sys.stdout.flush()
    sniff(
        filter="udp and port 4321", iface=iface,
        prn=lambda x: handle_pkt(x)  # Call handle_pkt for each captured packet
    )


if __name__ == '__main__':
    main()
