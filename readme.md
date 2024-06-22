# Merkle-Hellman Knapsack Cryptosystem

## Description

Building the **Merkle-Hellman Knapsack Cryptosystem** involves three parts:
- Key Generation
- Encryption
- Decryption

At a high-level, in the **Merkle-Hellman Knapsack Cryptosystem**, all participants
go through key generation once to construct both a public key and a private
key, linked together in some mathematical way. Public keys are made publicly
available, whereas private keys are kept under lock and key (pun intended).
Usually, public keys will lead to some sort of encryption function, and private
keys will lead to some sort of decryption function, and in many ways they act as
inverses.

## Usage
```
Usage: knapsack.py [OPTIONS] [MESSAGE]

  Encrypt and decrypt a [MESSAGE] or a [PATH]. [MESSAGE] can be typed
  on the command line with no flags or arguments, or read from a file
  using the --file option.

  Using their private key, the sender can encrypt text intended for a
  specific recipient, meaning that the sender must have the recipient's
  public key. The encrypted text can only be decrypted by the recipient
  using the recipient's private key and the sender's public key. If
  either the sender or the recipient lacks keys, they can be generated
  using the --generate option.

Options:
  -f, --file PATH  File to encrypt.
  -d, --decrypt    Decrypt previously encrypted
                   message.
  -k, --keys       Print the keys.
  -g, --generate   Generate keys for a user.
  --version        Show the version and exit.
  --help           Show this message and exit.

If [MESSAGE] or [PATH] is provided, encryption occurs by default (--encrypt
is optional). If [MESSAGE] or [PATH] is absent, decryption occurs by
default (--decrypt is optional). This cryptosystem can only encrypt
text containing valid UTF-8. Use double-quotes ("...") if [PATH] or
[MESSAGE] includes spaces.

  All encrypted messages are stored in "encoded.json". Public and
  private keys are stored in a json file named after the user.

  EXAMPLE USAGE:

     knapsack.py --generate --> keys for a specified user

     knapsack.py "The boats launch at midnight." --> encrypts the message

     knapsack.py (with no arguments) --> decrypts "encoded.json"
```

## Dependencies

- [click](https://click.palletsprojects.com/en/8.1.x/) (for command-line interface)
- [rich](https://pypi.org/project/rich/) (for pretty printing)