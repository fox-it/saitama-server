import base64
import binascii

from saitama.utils.mersenne_twister import MersenneTwister

CHARACTER_SET = "abcdefghijklmnopqrstuvwxyz0123456789"
BASE32_ALPHABET_OF_SAMPLE = "razupgnv2w01eos4t38h7yqidxmkljc6b9f5"


def encode_int_into_str(value: int, alphabet: str, apply_padding: bool = False) -> str:
    # This is an implementation of the implant's method of converting an int to a string using an alphabet
    text = ""
    length = len(alphabet)

    while True:
        # Divide down the value
        value, index = divmod(value, length)

        # Prepend the character at this index to the to-be-returned string
        text = alphabet[index] + text

        # Equivalent of do-while loop: break out of the loop if we have fully divided the input number down
        if value <= 0:
            break

    if apply_padding:
        # Pad left with the first character of the given alphabet
        text = text.rjust(3, alphabet[0])
    return text


def decode_str_into_int(text: str, alphabet: str) -> int | None:
    # This is a function to 'invert' a string encoded using the implants' int-to-string function.

    length = len(alphabet)
    value = None
    for char in text:
        idx = alphabet.find(char)
        # This can be even shorter but I left it as is for readability
        if value is None:
            value = idx
        else:
            value *= length

    # A lot of information gets lost due to the way the encoding works. Because the implant rounds down, we have to
    # 'count up' to find out what the real start is of the counter. The maximum amount of attempts has to be so high
    # because the information loss can also occur in, say, the last time the implant divides down. Then, when we start
    # multiplying our way up, we can be way off because the 'rounding information loss' occurred at the number that
    # will be multiplied from.

    for _ in range(10000):
        if encode_int_into_str(value, alphabet, True) == text:
            return value
        value += 1

    return None


def decode_possibly_padded_str_into_int(text: str, alphabet: str) -> int:
    # Sometimes the int that has been converted to a string was padded, for example when
    # sending the buffer size during command output transmission. If so, we need to try with padding to see if
    # we can still arrive at a valid decoding.

    without_padding = decode_str_into_int(text, alphabet)
    if without_padding is not None:
        return without_padding

    if not text.startswith(alphabet[0]):
        # If the input variable doesn't even start with the padding character, this is never going to work
        raise ValueError(f"Could not decode {text}")

    # As the padding can be either 1 or 2 characters, we try both.
    padding_once = input[1:]
    attempt = decode_str_into_int(padding_once, alphabet)
    if attempt is not None:
        return attempt

    # As the assumption of 'padded once' did not work, let's now try with 'padded twice' assumption
    padding_twice = input[2:]
    attempt = decode_str_into_int(padding_twice, alphabet)
    if attempt is not None:
        return attempt
    raise ValueError(f"Could not decode {input}")


def determine_shuffled_alphabet_from_seed(seed: int, original_alphabet: str) -> str:
    # This is a python implementation of the alphabet shuffle function of the implant
    ret = ""
    twister = MersenneTwister(seed)
    alphabet_length_at_start = len(original_alphabet)

    for _ in range(alphabet_length_at_start):
        # Get a 'random' number from the Mersenne twister (implant and server share the same seed for the twister)
        random_number = twister.random()

        # Re-determine the current length of the alphabet set we now have, because every iteration we will 'pop off'
        # a character
        current_alphabet_length = len(original_alphabet)

        # Modulo the randomly generated number with the current length of the alphabet set, so that you never have
        # an out-of-range index value
        random_index_in_alphabet = random_number % current_alphabet_length

        # Grab the character that resides at this index and append it to the to-be-returned value
        ret += original_alphabet[random_index_in_alphabet]

        # Now 'pop off' this character from the alphabet set
        original_alphabet = remove_char(original_alphabet, random_index_in_alphabet)

    return ret


def remove_char(str, n):
    first_part = str[:n]
    last_part = str[n + 1 :]
    return first_part + last_part


def bruteforce_base32(chunk: str) -> bytes:
    chunk = chunk.upper()
    chunk_shorter = chunk[:-1]
    for i in range(10):
        try:
            decoded_chunk = base64.b32decode(chunk + ("=" * i))
            return decoded_chunk
        except binascii.Error:
            try:
                decoded_shorter_chunk = base64.b32decode(chunk_shorter + ("=" * i))
                return decoded_shorter_chunk
            except binascii.Error:
                pass

    raise ValueError(f"Could not bruteforce-decode {chunk}")
