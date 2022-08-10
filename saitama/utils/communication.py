from collections import namedtuple

BeaconResponse = namedtuple("BeaconResponse", ["ip_address", "beacon_result"])
BeaconResult = namedtuple("BeaconResult", ["result_code", "result_data"])
DnsPair = namedtuple("DnsPair", ["qname", "rdata"])


class ResultCodes:
    COMMAND_OUTPUT = 1
