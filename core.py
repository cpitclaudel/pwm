import json
import os
import os.path
import re
import base64
from collections import namedtuple, OrderedDict

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512
from Crypto.Protocol.KDF import PBKDF2

class InvalidKeyException(Exception):
    pass

KeyPair = namedtuple("KeyPair", ("encryption_key", "digest_key"))

class Encryption:
    @staticmethod
    def b64encode(bytestring):
        return base64.b64encode(bytestring).decode('ascii')

    @staticmethod
    def b64decode(string):
        return base64.b64decode(string.encode('ascii'))

    @staticmethod
    def derive_keys(password, salt):
        bs = PBKDF2(password, salt, dkLen=64, count=5000)
        return KeyPair(encryption_key=bs[:32], digest_key=bs[32:])

class Message(object):
    def __init__(self, iv, salt, digest, ciphertext):
        self.iv = iv
        self.salt = salt
        self.digest = digest
        self.ciphertext = ciphertext

    @staticmethod
    def encrypt(cleartext, password):
        iv, salt = os.urandom(AES.block_size), os.urandom(32)
        keys = Encryption.derive_keys(password, salt)
        ciphertext = AES.new(keys.encryption_key, AES.MODE_CFB, iv).encrypt(cleartext)
        digest = HMAC.new(keys.digest_key, ciphertext, SHA512).digest()
        return Message(iv, salt, digest, ciphertext)

    def decrypt(self, password):
        keys = Encryption.derive_keys(password, self.salt)
        digest = HMAC.new(keys.digest_key, self.ciphertext, SHA512).digest()
        if digest == self.digest:
            return AES.new(keys.encryption_key, AES.MODE_CFB, self.iv).decrypt(self.ciphertext).decode("utf-8")
        else:
            raise InvalidKeyException()

    def serialize(self):
        js = OrderedDict([("iv", Encryption.b64encode(self.iv)),
                          ("salt", Encryption.b64encode(self.salt)),
                          ("digest", Encryption.b64encode(self.digest)),
                          ("ciphertext", Encryption.b64encode(self.ciphertext))])
        return js

    @staticmethod
    def deserialize(js):
        iv = Encryption.b64decode(js["iv"])
        salt = Encryption.b64decode(js["salt"])
        digest = Encryption.b64decode(js["digest"])
        ciphertext = Encryption.b64decode(js["ciphertext"])
        return Message(iv, salt, digest, ciphertext)

class Password(object):
    def __init__(self, domain, username, clear_password, master_password):
        self.domain = domain
        self.username = username
        self.encrypted_password = Message.encrypt(clear_password, master_password)

    def serialize(self):
        js = OrderedDict([("domain", self.domain),
                          ("username", self.username),
                          ("encrypted_password", self.encrypted_password.serialize())])
        return js

    def cleartext(self, master_password):
        return self.encrypted_password.decrypt(master_password)

    @property
    def sort_index(self):
        return self.domain, self.username

    @classmethod
    def deserialize(cls, js):
        pwd = cls.__new__(cls)
        pwd.domain = js["domain"]
        pwd.username = js["username"]
        pwd.encrypted_password = Message.deserialize(js["encrypted_password"])
        return pwd

    def __repr__(self):
        return "Password({}, {})".format(self.domain, self.username)

class PasswordDatabase(object):
    def __init__(self):
        self.passwords = []

    def add(self, pw):
        self.passwords.append(pw)

    def remove(self, predicate):
        self.passwords = [pw for pw in self.passwords if not predicate(pw)]

    def find(self, predicate):
        return sorted((pw for pw in self.passwords if predicate(pw)), key=lambda pw: pw.sort_index)

    @classmethod
    def deserialize(cls, js):
        db = cls.__new__(cls)
        db.passwords = [Password.deserialize(pw) for pw in js["passwords"]]
        return db

    def serialize(self):
        return OrderedDict([("passwords", [p.serialize() for p in self.passwords])])

class PasswordStore(object):
    def __init__(self):
        self.db = PasswordDatabase()

    @classmethod
    def deserialize(cls, js, master_password):
        store = cls.__new__(cls)
        db_js = Message.deserialize(js["db"]).decrypt(master_password)
        store.db = PasswordDatabase.deserialize(json.loads(db_js))
        return store

    @staticmethod
    def read_from(path, master_password):
        try:
            with open(path) as infile:
                return PasswordStore.deserialize(json.load(infile), master_password)
        except FileNotFoundError:
            return PasswordStore()

    def serialize(self, master_password):
        db_js = json.dumps(self.db.serialize(), indent=True)
        return OrderedDict([("db", Message.encrypt(db_js, master_password).serialize())])

    def save_to(self, path, master_password):
        if os.path.exists(path):
            backup = path + ".bak"
            os.rename(path, backup)
        with open(path, mode="w") as outfile:
            js = self.serialize(master_password)
            json.dump(js, outfile, indent=True)

class PasswordPredicates(object):
    @staticmethod
    def regexp(domain=None, username=None):
        domain, username = domain or ".*", username or ".*"
        return lambda pw: (re.search(domain, pw.domain, re.IGNORECASE) and re.search(username, pw.username, re.IGNORECASE))

    @staticmethod
    def exact(domain, username):
        return lambda pw: (domain == pw.domain and username == pw.username)

class PasswordManager(object):
    def __init__(self, store_path, master_password, mode="r"):
        self.store = None
        self.store_path = store_path
        self.master_password = master_password
        self.mode = mode

    def __enter__(self):
        self.store = PasswordStore.read_from(self.store_path, self.master_password)
        return self.store.db

    def __exit__(self, *exc_info):
        if self.store != None and self.mode == "w":
            self.store.save_to(self.store_path, self.master_password)
