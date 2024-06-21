"""
knapsack.py
Richard E. Rawson
2024-03-07

Building the Merkle-Hellman Cryptosystem involves three parts:
    -- Key Generation
    -- Encryption
    -- Decryption

At a high-level, in the Merkle-Hellman Knapsack Cryptosystem, all participants
go through key generation once to construct both a public key and a private
key, linked together in some mathematical way. Public keys are made publicly
available, whereas private keys are kept under lock and key (pun intended).
Usually, public keys will lead to some sort of encryption function, and private
keys will lead to some sort of decryption function, and in many ways they act as
inverses.
"""

import json
import random
from math import gcd
from pathlib import Path

import click
from icecream import ic
from rich import print

VERSION = "0.2"


@click.command(epilog='If [MESSAGE] or [PATH] is provided, encryption occurs by default (--encrypt is optional). If [MESSAGE] or [PATH] is absent, decryption occurs by default (--decrypt is optional). This cryptosystem can only encrypt text containing valid UTF-8. Use double-quotes ("...") if [PATH] or [MESSAGE] includes spaces.\n\nAll encrypted messages are stored in "encoded.json". Public and private keys are stored in a json file named after the user.\n\nEXAMPLE USAGE:\n\n   knapsack.py "The boats launch at midnight." --> encrypts the message\n\n   knapsack.py (with no arguments) --> decrypts "encoded.json"')
# @click.option("-m", "--message", "msg", type=str, multiple=True, help='Message to encrypt')
@click.argument("message", type=str, required=False)
@click.option("-f", "--file", type=click.Path(exists=True), help='File to encrypt.')
@click.option("-d", "--decrypt", is_flag=True, default=False, help='Decrypt previously encrypted message.')
@click.option("-k", "--keys", is_flag=True, default=False, help="Print the keys.")
@click.option("-g", "--generate", is_flag=True, default=False, help="Generate keys for a user.")
@click.version_option(version=VERSION)
def cli(message: str, file: str, decrypt: str, keys: str, generate: str) -> None:
    """
    Encrypt and decrypt a [MESSAGE] or a [PATH]. [MESSAGE] can be typed on the command line with no flags or arguments, or read from a file using the --file option.

    Text is encrypted for a specific user, meaning that we must have that user's public key. The encrypted text can only be decrypted using that user's private key. If a user doesn't have keys, they can generate them using the --generate option.

    \f
    Encryption takes precendence over decryption. This means that if a message AND --decrypt are found on the command line (in any order), the message will be encrypted but "encoded.json" will not be decrypted. If both a [PATH] and a [MESSAGE] are provided, the [PATH] takes precedence and the [MESSAGE] will not be encrypted.

    Parameters
    ----------
    message : str -- message to encrypt
    file : Path -- filename containing text to encrypt
    decrypt : str -- flag to decrypt "encoded.json"
    keys : str -- flag to print public and private keys
    generate: str -- flag to generate a private key
    """

    # print()
    # ic(message, file, decrypt, keys, generate)
    # print()

    # The following prevents the 'Parameter declaration "message" is obscured by a declaration of the same name.' error.
    if message:
        msg: str = message
    else:
        msg = ""

    if keys:
        print_keys()
        return

    if generate:
        generate_keys()
        return

    # If the --file argument was included, read the file into "msg".
    # If the file does not exist, the CLI will report such and quit.
    if file:
        msg: str = read_file_to_encrypt(file)
        if not msg:
            return

    # If there's a message, either typed on the command line or provided in a file,
    # encrypt it. If no message was provided by either mechanism, then the user must be expecting to decrypt the contents of "encoded.json".
    if msg:
        receivers_keys: dict[str, Any] = get_receiver_keys("encrypting")
        public_key: list[int] = receivers_keys['public_key']
        encrypted_message: str = encrypt_msg(msg, public_key)

        print(encrypted_message)
        write_coded(encrypted_message)

    else:
        # We get here if no message was provided. The assumption is that the user
        # wants to decrypt a file... if "encoded.json" exists!
        if Path("encoded.json").exists():
            # fmt: ON
            encoded_msg: str = read_encoded_msg()
            receivers_keys = get_receiver_keys("decrypting")
            decrypted_msg: str = decrypt_msg(encoded_msg, receivers_keys['s'], receivers_keys['q'], receivers_keys['r'])
            # fmt: OFF
            print(f'DECRYPTED MESSAGE\n[blue]{decrypted_msg}[/]', sep="")
            return
        else:
            print(
                'Error: The file "encoded.json" containing encrypted text was not found.')
            return None

def get_receiver_keys(action: str) -> dict[str, any]:
    """
    Retrieve the keys from the user's json file. Format of this file:

    {
        "public_key": [2864, 2145, 2840, 3541, 1246, 1150, 2449, 1160],
        "s": [6, 7, 26, 40, 158, 238, 950, 1426],
        "q": 3589,
        "r": 2870
    }

    Parameters
    ----------
    action : str -- either "encrypting" or "decrypting"

    Returns
    -------
    dict -- dictionary containing a specific user's keys
    """

    print()
    if action == "encrypting":
        receiver_name: str = input("Who will receive this encrypted message? ").lower()
    else:
        receiver_name: str = input("Who is decrypting this message: ").lower()
    filename: str = receiver_name + ".json"
    try:
        with open(filename, 'r') as f:
            receivers_keys = json.load(f)
    except FileNotFoundError:
        print(f"\nYou do not have {receiver_name}'s public key,\nwhich is required for encryption.")
        exit()

    return receivers_keys


# ==== KEY GENERATION ==========================================

class MerkleHellmanKeys:
    def __init__(self, public_key, s, q, r) -> None:
        self.public_key = public_key
        self.s: int = s
        self.q: int = q
        self.r: int = r

def is_coprime(a, b) -> bool:
    """
    This function determines whether or not two integers are coprime, meaning that there are no numbers that divide them both, other than 1. This function is used in generate_keys().
    """

    # If GCD is 1, the numbers are coprime
    return gcd(a, b) == 1

def generate_keys() -> MerkleHellmanKeys:
    """
    Generate Merkle-Hellman keys, including both public and private keys. Keys are stored in a json file named after the user.
    """

    rng = random.SystemRandom()

    # Create a superincreasing sequence [s].
    initial: int = rng.randint(2, 10)
    s: list[int] = [initial]

    next_val = 0
    chunk_size = 8
    for i in range(chunk_size // 2):
        next_val = sum(s) + 1
        s.append(next_val)
        if i < (chunk_size // 2 - 1):
            next_val = sum(s) * 2
            s.append(next_val)

    # Create q: random number larger than the sum of [s]
    sum_s: int = sum(s)
    q: int = rng.randint(sum_s + 1, sum_s * 2)

    # Create random integer 'r' such that 'gcd(r, q) = 1'
    # (i.e., r and q are coprime)
    cop = False
    r = 0
    while not cop:
        r: int = rng.randint(2, q - 1)
        cop: bool = is_coprime(r, q)

    # Calculate the vector public_key = [b_1, b_2, ..., b_n], where each member of the [s] is multiplied by r and then divided (modulo) q
    # public_key is r * [s](i) % q
    public_key: list[int] = [(si * r) % q for si in s]

    user_keys: dict = {'public_key': public_key, "s": s, "q": q, "r": r}
    print('\nThe name you enter will be the filename for the keys.', sep='')
    filename: str = input("Whose keys are these: ").lower()
    filename += ".json"
    with open(filename, 'w') as f:
        json.dump(user_keys, f)

    return

# ==== END OF KEY GENERATION ===================================

def print_keys() -> None:
    """
    Print the public and private keys for a specified user.
    """

    user_name: str = input("Whose keys do you want to print? ").lower()

    if user_name:
        # Read the "user_name" json file and then parse the keys that are returned.
        try:
            with open(user_name + ".json", 'r') as f:
                encryption_keys = json.load(f)
            public_key = encryption_keys['public_key']
            s: int = encryption_keys['s']
            q: int = encryption_keys['q']
            r: int = encryption_keys['r']

            # pk_list: list[str] = [str(x) for x in public_key]
            # pk_str: str = ", ".join(pk_list)

            # s_list: list[str] = [str(x) for x in s]
            # s_str: str = ", ".join(s_list)

            print(f'PUBLIC KEY:\n{public_key}\n\nPRIVATE KEY\ns: {s}\nq: {q}\nr: {r}', sep="")
        except FileNotFoundError:
            print(f"Error: The file {user_name}.json containing the keys was not found.")
            return
    else:
        return


def encrypt_msg(message: str, public_key: list[int]) -> str:
    """
    Encrypt the message passed in on the command line as either a string of text or a file.

    If Bob is the receiver, then we use Bob's public key (provided as an argument) to encode the message. For Bob to decrypt the message, he will require his private key, since his public key was used to encrypt the message.

    Parameters
    ----------
    message : str -- the string to encrypt
    public_key : list[int] -- Bob's public key

    Returns
    -------
    str -- encrypted message, comprising a string of integers.
    """

    # Step 1: convert all the characters in msg to bytes and then to binary.
    msg_binary: list[str] = [bin(ord(c)) for c in message]
    msg_binary_list: list[str] = [format(int(x[2:]), '08') for x in msg_binary]

    # Step 2: All the elements –  s1,  s2,  s 3, .... sn of the sequence s are multiplied  with the number r and the modulus of the multiple is taken by dividing with the number a. Therefore, pi = r*si mod(a). This is the public_key.

    # Step 3: Each element of the public key (p1, p2, p3, ....  pn) is multiplied with the corresponding element of the binary sequence [msg_binary_vec]. The numbers are then added to create the encrypted message M(i).
    sum: int = 0
    encrypted_msg_list: list[str] = []
    a: int = 0

    for b in msg_binary_list:
        b_int: list[int] = [int(x) for x in b]
        z = zip(public_key, b_int)
        for (x, y) in z:
            a = x * y
            sum += a
        encrypted_msg_list.append(str(sum))
        sum = 0

    encrypted_message: str = " ".join(encrypted_msg_list)

    return encrypted_message


def decrypt_msg(encoded_msg: str, s: list[int], q: int, r: int) -> str:
    """
    Decrypt the encrypted message using only the private key (s, q, and r).

    Bob's public key was used to encode the message, so Bob will need his private key (s, q, r) to decrypt the message.

    Parameters
    ----------
    encoded_msg : str -- the message to decrypt
    s : list[int] -- s
    q : int -- q
    r : int -- r

    Returns
    -------
    str -- the decrypted message
    """

    # Put contents of the single string "encoded_msg" into a list of ints.
    msg_list: list[int] = [int(x) for x in encoded_msg.split(" ")]

    # Step 1: calculate the modular multiplicative inverse of r in r mod q.
    r_inv: int = modular_inverse(q, r)

    # Step 2:
    #    (i) "step" = multiply each element of the encrypted message (M) with r-1 mod q.
    #   (ii) Find the largest number in the sequence [s], which is smaller than step.
    #  (iii) Continue... The largest number in the sequence [s], which is smaller than 28 is 25.
    #   (iv) loop back to iii.
    step = 0
    second = 0
    index = 0
    indices: list[int] = []
    binary_list: list[str] = []
    this_binary: str = ""

    try:
        for el in msg_list:
            step = (el * r_inv) % q
            while True:
                # Find the largest number in [s] that is smaller than step.
                second: int = max(filter(lambda x: x <= step, s))
                # Find the position of "step" in [s].
                index: int = s.index(second)
                step -= second
                indices.append(index)
                if step == 0:
                    break

            # Create a binary string from [indices].
            this_binary = create_binary_string(indices)
            binary_list.append(this_binary)
            indices.clear()
    except ValueError:
        print("Access denied. Cannot decrypt with the provided key.")
        exit()

    # Convert each element in [binary_vec] to an ASCII value and then to a letter.
    char_list: list[str] = []
    for b in binary_list:
        this_char: str = chr(int(b, 2))
        char_list.append(this_char)

    return "".join(char_list)


# ==== UTILITY FUNCTIONS ====================================
def create_binary_string(indices) -> str:
    """
    This function takes a list of indexes and changes the elements of the list ["0", "0", "0", "0", "0", "0", "0", "0"] from 0 to 1 at those positions. For example, if 'indices' contains [1, 5], then this function will return ["0", "1", "0", "0", "0", "1", "0", "0"].

    This function is called from decrypt_msg().

    Parameters
    ----------
    indices : list -- list of indices in a list

    Returns
    -------
    str -- the modified list of integers in the binary string.

    Examples
    --------
    indices = [6, 3, 2, 1]
    base_bin_list if populated accordingly: [0', '1', '1', '1', '0', '0', '1', '0']
    """
    base_bin_list: list[str] = ["0", "0", "0", "0", "0", "0", "0", "0"]
    for i in indices:
        base_bin_list[i] = "1"
    return ''.join(base_bin_list)

def read_encoded_msg() -> str:
    """
    Read the encrypted file ("encoded.json").

    Returns
    -------
    str -- encrypted message in "encoded.json"
    """

    with open(file="encoded.json", mode="r", encoding='utf-8') as file:
        data = json.load(file)
    return data["encrypted_msg"]


def write_coded(encrypted_message: str) -> None:
    """
    Save the encrypted message to the "encoded.json" file.

    Parameters
    ----------
    encrypted_message : str -- the encrypted message
    """

    these_keys = {
        "encrypted_msg": encrypted_message,
        # "public_key": encryption_keys.public_key,
        # "s": encryption_keys.s,
        # "q": encryption_keys.q,
        # "r": encryption_keys.r
    }

    # Write the data to a file in JSON format. "encoded.json" will be overwritten if it already exists.
    with open("encoded.json", "w") as file:
        json.dump(these_keys, file)


def read_file_to_encrypt(file: str) -> str:
    """
    If the user wants to encrypt text in a file, this function simply reads that file and returns its contents as a single string.

    Parameters
    ----------
    file : str -- filename

    Returns
    -------
    str -- the text that will be encrypted
    """

    try:
        with open(file=file, mode='r', encoding='utf-8') as f:
            all_lines: list[str] = f.readlines()

    except FileNotFoundError:
        print(f"The file {file} does not exist.")
        return ""

    # all_lines = [line.strip("\n") for line in all_lines]
    return "".join(all_lines)


def modular_inverse(q: int, r: int) -> int:
    """
    Calculate the modular inverse of r.
    """
    a, b = r, q
    saved: int = b
    x, y = 0, 1
    u, v = 1, 0

    while a != 0:
        q = b // a
        r = b % a
        m: int = x - u * q
        n: int = y - v * q
        b: int = a
        a: int = r
        x: int = u
        y: int = v
        u: int = m
        v: int = n

    x %= saved
    if x < 0:
        x += saved
    return x


if __name__ == '__main__':
    print()
    cli()
