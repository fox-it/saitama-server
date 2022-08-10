import argparse
import logging
import os

from scapy.all import DNSQR, DNSRR, rdpcap

from saitama.server import SaitamaServer
from saitama.utils.colors import Colors
from saitama.utils.communication import DnsPair

logger = logging.getLogger("dns_c2")


class C2Replay:
    def __init__(self, c2_server: SaitamaServer, c2_domains: list[str]) -> None:
        self.c2_server = c2_server
        self.c2_domains = c2_domains
        self.memory = {}

    def replay_request(self, pair: DnsPair) -> None:
        dns_query = pair.qname
        rdata = pair.rdata

        # Process dns request within c2 if we haven't seen this request before.
        from_cache = True
        if dns_query not in self.memory.keys():
            self.memory[dns_query] = self.c2_server.parse_dns_request_and_answer(dns_query, rdata)
            from_cache = False
        response = self.memory[dns_query]
        cache_string = " (cached)" if from_cache else ""
        logging.debug(
            f"{Colors.GREEN}{dns_query}{Colors.RESET} --> {Colors.GREEN}{response} {cache_string}{Colors.RESET}"
        )

    def parse_pcap(self, pcap_path) -> None:
        pcap_flow = rdpcap(pcap_path)

        dns_pairs = []
        for packet in pcap_flow:
            if DNSQR in packet:
                qname = packet[DNSQR].qname.decode("utf-8")

                # Hotfix
                if qname.endswith("."):
                    qname = qname[:-1]

                if not any(domain in qname for domain in self.c2_domains):
                    continue
                rdata = None
                if DNSRR in packet:
                    rdata = packet[DNSRR].rdata
                    if isinstance(rdata, list) and len(rdata) == 1:
                        rdata = rdata[0]
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("ascii")
                    rdata = str(rdata)
                    dns_pairs.append(DnsPair(qname, rdata))
        self.c2_server.prepare_for_replay(dns_pairs)
        for pair in dns_pairs:
            self.replay_request(pair)


def main():
    parser = argparse.ArgumentParser(description="Replay a recording of C2 traffic")
    parser.add_argument(
        "-v",
        "--verbose",
        help="Set logging level to debug",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.INFO,
    )

    parser.add_argument(
        "-d",
        "--domain",
        help="C2 Domains for the C2 Server. Parameter can be passed multiple times.",
        action="append",
        dest="domains",
        required=True,
    )

    parser.add_argument(
        "-f",
        "--file",
        help="PCAP to replay from.",
        dest="filename",
        required=True,
    )
    args = parser.parse_args()
    logging.basicConfig(format="%(asctime)s : %(message)s", datefmt="%H:%M:%S", level=args.loglevel)
    domains = args.domains
    filename = args.filename
    c2_server = SaitamaServer(domains)

    replay = C2Replay(c2_server, domains)
    if (not filename.lower().endswith(".pcap")) and (not filename.lower().endswith(".pcapng")):
        raise ValueError("File should be a pcap")
    if not os.path.exists(filename):
        raise ValueError("File does not exist")

    replay.parse_pcap(filename)


if __name__ == "__main__":
    main()
