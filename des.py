from Crypto.Cipher import DES
import logging
from six.moves import input  # python2/3 compatibility
import functools

logger = logging.getLogger()


def encrypt(key, plain_text):
    """Encrypt using single-round-DES"""
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plain_text)


def decrypt(key, cipher_text):
    """Decrypt using single-round DES"""
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(cipher_text)


def nth_key(index):
    """Gets the nth key with respect to parity bits"""
    keystring = []

    for i in range(8):
        key_byte = index & 127  # 127 == int('1111111', 2)
        hamming_weight = bin(key_byte).count('1')
        if hamming_weight % 2 == 0:
            keystring.append(((key_byte << 1) + 1))
        else:
            keystring.append((key_byte << 1))

        index >>= 7

    return bytes(keystring[::-1])  # reverse order


def _precompute(plain_text, key):
    return (encrypt(key, plain_text), key)


def meet_in_the_middle(nbits, text_pairs, pool=None):
    logger.info("Pre-computing")

    plain_text, cipher_text = text_pairs[0]
    key_generator = (nth_key(i) for i in range(0, 2**nbits))
    if pool is None:
        table = dict([_precompute(plain_text, key) for key in key_generator])
    else:
        table = dict(pool.map(functools.partial(_precompute, plain_text),
                              key_generator, 1000))

    logger.info("precomputed {} items".format(len(table)))

    logger.info("Cracking cipher_text")
    for key in (nth_key(i) for i in range(0, 2**nbits)):
        candidate = decrypt(key, cipher_text)
        if candidate in table:
            logger.info("Found key: ({}, {})".format(table[candidate], key))
            for plain, cipher in text_pairs[1:]:
                if not decrypt(key, cipher) == encrypt(key, plain):
                    continue  # incorrect candidate

            return (table[candidate], key)


def run(argv=None):
    """Run the program

    Usage: des.py [options] <bits>

    It will ask you for further inputs

    Options::
        -h,--help           Show this help
        -v,--verbose        Increase verbosity
        --test              Get a test string
    """
    import sys
    import docopt
    import textwrap
    from binascii import unhexlify, hexlify
    from multiprocessing import Pool

    argv = sys.argv[1:]
    args = docopt.docopt(textwrap.dedent(run.__doc__), argv)

    nbits = int(args['<bits>'])

    # set up logging
    level = logging.WARN
    if args['--verbose']:
        level = logging.INFO
    logging.basicConfig(level=level)

    if args['--test']:
        from random import randint
        key1 = nth_key(randint(0, 2**nbits))
        key2 = nth_key(randint(0, 2**nbits))
        plain_text = bytes((randint(0, 255) for i in range(8)))
        cipher_text = encrypt(key2, encrypt(key1, plain_text))
        print("key: ({}, {})".format(hexlify(key1).decode('utf-8'),
                                     hexlify(key2).decode('utf-8')))
        print("plain text:  {}".format(hexlify(plain_text).decode('utf-8')))
        print("cipher text: {}".format(hexlify(cipher_text).decode('utf-8')))
        return

    input_more = True
    pairs = []
    while input_more:
        plain_text = unhexlify(
            input("Please input the plain text, hex encoded: "
                  ).strip().encode('utf-8'))
        cipher_text = unhexlify(
            input("Please input the cipher text, hex encoded: "
                  ).strip().encode('utf-8'))
        pairs.append((plain_text, cipher_text))
        if 'y' not in input("Do you want to supply more texts? [y/N]: "):
            input_more = False

    with Pool() as p:
        keys = meet_in_the_middle(nbits, pairs, pool=p)
    if keys:
        print("Found keys: ({}, {})".format(*keys))
    else:
        print("Did not find keys!")

if __name__ == '__main__':
    run()
