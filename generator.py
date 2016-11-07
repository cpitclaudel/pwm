import os
import random
import string
from typing import *

class PasswordGenerator:
    @staticmethod
    def sequence(length, *pools):
        """Generate a random password.
        The final sequence is LENGTH tokens long.  Each token is taken from one of
        POOLS.  The final password contains at least one token from each pool."""

        rng = random.SystemRandom()
        pools = tuple(list(pool) for pool in pools)
        large_pool = [token for pool in pools for token in pool]

        length = max(length, len(pools))
        tokens = [rng.choice(pool) for pool in pools]
        tokens.extend([rng.choice(large_pool) for _ in range(length - len(tokens))])

        return tokens

    @staticmethod
    def password(length):
        pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
        return "".join(PasswordGenerator.sequence(length, *pools))

    @staticmethod
    def letters_string(length):
        pools = [string.ascii_lowercase, string.ascii_uppercase, " "]
        return "".join(PasswordGenerator.sequence(length, *pools))

    @staticmethod
    def passphrase(length):
        words = [line.strip() for line in open("/usr/share/dict/words")]
        ascii_letters = set(string.ascii_letters)
        ascii_words = [word for word in words if all(c in ascii_letters for c in word)]
        phrase = PasswordGenerator.sequence(length, ascii_words)
        suffix = PasswordGenerator.sequence(3, string.ascii_uppercase, string.digits, string.punctuation)
        return " ".join(phrase + ["".join(suffix)])
