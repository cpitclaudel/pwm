import sys
import os.path
from getpass import getpass
from argparse import ArgumentParser

import xerox
from tabulate import tabulate

from time import sleep
from .generator import PasswordGenerator
from .core import Password, PasswordManager, PasswordStore, PasswordPredicates, InvalidKeyException

def print_err(*args, **kwargs):
    kwargs.update(file=sys.stderr, flush=True)
    print(*args, **kwargs)

def query(header, prompt, answer=None, default=None):
    while answer is None:
        print_err(header + " ", end="")
        answer = prompt("") or default
    return answer

class PasswordDriver(object):
    @staticmethod
    def add_domain(args):
        args.domain = query("Domain?", input, args.domain)

    @staticmethod
    def add_username(args):
        args.username = query("Username?", input, args.username)

    @staticmethod
    def add_password(args):
        needs_new_input = (args.password == None)
        account = PasswordDriver.format_account(args)
        while needs_new_input:
            args.password = query("Enter password for {}:".format(account), getpass)
            password_again = query("Retype password:", getpass)
            needs_new_input = password_again != args.password
            if needs_new_input:
                print_err("Passwords did not match.")

    @staticmethod
    def format_account_helper(domain, username):
        if username is not None and domain is not None:
            return "'{}' @ '{}'".format(username, domain)
        elif username is not None:
            return "username '{}'".format(username)
        elif domain is not None:
            return "domain '{}'".format(domain)

    @staticmethod
    def format_account(args):
        return PasswordDriver.format_account_helper(args.domain, args.username)

    @staticmethod
    def put_query_overwrite(account):
        qstring = "Account {} already exists; update? [Y/n]".format(account)
        return query(qstring, input, default="") in "yY"

    @staticmethod
    def find_conflicts(db, pwd, master_pwd):
        duplicates, conflicts = [], []
        for other in db.find(PasswordPredicates.exact(pwd.domain, pwd.username)):
            same = pwd.cleartext(master_pwd) == other.cleartext(master_pwd)
            (duplicates if same else conflicts).append(other)
        return conflicts, duplicates

    @staticmethod
    def put_helper(args, db):
        account = PasswordDriver.format_account(args)
        new = Password(args.domain, args.username, args.password, args.master_password)
        conflicts, duplicates = PasswordDriver.find_conflicts(db, new, args.master_password)
        if (not conflicts) or PasswordDriver.put_query_overwrite(account):
            print_err("Creating or updating record {}.".format(account))
            db.remove(lambda x: x in conflicts or x in duplicates)
            db.add(new)
            return new

    @staticmethod
    def put(args):
        PasswordDriver.add_domain(args)
        PasswordDriver.add_username(args)
        PasswordDriver.add_password(args)
        with PasswordManager(args.password_store, args.master_password, mode="w") as db:
            return PasswordDriver.put_helper(args, db)

    @staticmethod
    def generate_pwd(args):
        if args.simple:
            generator = PasswordGenerator.letters_string
            args.length = args.length or 10
        elif args.no_passphrase:
            generator = PasswordGenerator.password
            args.length = args.length or 10
        else:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f]
            generator = lambda l: PasswordGenerator.passphrase(wordlist, l)
            args.length = args.length or 5
        args.password = generator(args.length)

    @staticmethod
    def new(args):
        PasswordDriver.add_domain(args)
        PasswordDriver.add_username(args)
        PasswordDriver.generate_pwd(args)
        new_pwd = PasswordDriver.put(args)
        if new_pwd:
            PasswordDriver.run_action_on_pw(args, new_pwd)

    @staticmethod
    def gen(args):
        PasswordDriver.generate_pwd(args)
        print_err(args.password)

    @staticmethod
    def print_accounts(pwds, master_password=None):
        if master_password:
            pwds = [(pw.domain, pw.username, pw.cleartext(master_password)) for pw in pwds]
            headers = ("Domain", "Username", "Password")
        else:
            pwds = [(pw.domain, pw.username) for pw in pwds]
            headers = ("Domain", "Username")
        print_err(tabulate(pwds, headers=headers, tablefmt="rst"))

    @staticmethod
    def warn_if_no_records_found(args, pwds):
        if len(pwds) == 0:
            print_err("No record found for {}.".format(PasswordDriver.format_account(args)))
            return True

    @staticmethod
    def warn_if_more_than_one_record_found(args, pwds):
        if len(pwds) > 1:
            print_err("Multiple records found for {}.".format(PasswordDriver.format_account(args)))
            return True

    @staticmethod
    def run_action_on_pw(args, pwd):
        args.pw_action(pwd.cleartext(args.master_password), PasswordDriver.format_account(pwd))

    @staticmethod
    def get(args):
        if not args.domain:
            PasswordDriver.add_domain(args)
            PasswordDriver.add_username(args)
        with PasswordManager(args.password_store, args.master_password) as db:
            pwds = db.find(PasswordPredicates.regexp(args.domain, args.username))
            if not PasswordDriver.warn_if_no_records_found(args, pwds):
                if PasswordDriver.warn_if_more_than_one_record_found(args, pwds):
                    PasswordDriver.print_accounts(pwds)
                _, shortest = min(((len(pwd.username), len(pwd.domain)), pwd) for pwd in pwds)
                PasswordDriver.run_action_on_pw(args, shortest)

    @staticmethod
    def print(args):
        args.pw_action = PasswordActions.print
        return PasswordDriver.get(args)

    @staticmethod
    def exact(args):
        PasswordDriver.add_domain(args)
        PasswordDriver.add_username(args)
        with PasswordManager(args.password_store, args.master_password) as db:
            pwds = db.find(PasswordPredicates.exact(args.domain, args.username))
            if not (PasswordDriver.warn_if_no_records_found(args, pwds) or
                    PasswordDriver.warn_if_more_than_one_record_found(args, pwds)):
                PasswordDriver.run_action_on_pw(args, pwds[0])

    @staticmethod
    def delete(args):
        PasswordDriver.add_domain(args)
        PasswordDriver.add_username(args)
        with PasswordManager(args.password_store, args.master_password, mode="w") as db:
            pwds = db.find(PasswordPredicates.exact(args.domain, args.username))
            if not (PasswordDriver.warn_if_no_records_found(args, pwds) or
                    PasswordDriver.warn_if_more_than_one_record_found(args, pwds)):
                db.remove(lambda x: x in pwds)
                print_err("Record deleted: {}".format(PasswordDriver.format_account(args)))

    @staticmethod
    def pwsearch(args):
        pattern = query("Pattern:", input)
        with PasswordManager(args.password_store, args.master_password, mode="w") as db:
            pwds = db.find(PasswordPredicates.cleartext_pattern(pattern, args.master_password))
            print_err()
            if not pwds:
                print_err("No records found")
            else:
                PasswordDriver.print_accounts(pwds)

    @staticmethod
    def pwned_search_response(response, sha1):
        bs = response.read()
        header = sha1[5:].upper() + b":"
        start = bs.find(header)
        if start >= 0:
            end = bs.find(b"\r\n", start)
            return int(bs[start + len(header):end if end >= 0 else None])
        return 0

    @staticmethod
    def pwned(args):
        import urllib.request
        API_ROOT = "https://api.pwnedpasswords.com/range/"
        USER_AGENT = "PWM-password-manager"
        with PasswordManager(args.password_store, args.master_password, mode="w") as db:
            for pwd in db.passwords:
                sha1 = pwd.sha1(args.master_password)
                query_url = API_ROOT + sha1[:5].decode('ascii')
                request = urllib.request.Request(query_url, None, {'User-Agent': USER_AGENT})
                with urllib.request.urlopen(request) as response:
                    print(PasswordDriver.format_account(pwd),
                          PasswordDriver.pwned_search_response(response, sha1))

    @staticmethod
    def search(args):
        if not args.domain:
            PasswordDriver.add_domain(args)
            PasswordDriver.add_username(args)
        with PasswordManager(args.password_store, args.master_password) as db:
            pwds = db.find(PasswordPredicates.regexp(args.domain, args.username))
            if not PasswordDriver.warn_if_no_records_found(args, pwds):
                master_password = args.master_password if args.pw_action is PasswordActions.print else None
                PasswordDriver.print_accounts(pwds, master_password)

    @staticmethod
    def read(args):
        with PasswordManager(args.password_store, args.master_password, mode="w") as db:
            with sys.stdin if args.file == "-" else open(args.file) as infile:
                for line in infile:
                    fields = line.strip().split("\t")
                    if fields:
                        if len(fields) >= 3:
                            args.username, args.domain, args.password, *_ = fields
                            PasswordDriver.put_helper(args, db)
                        else:
                            print_err("Dropping {}".format(fields))

    @staticmethod
    def recode(args):
        PasswordDriver.add_password(args)
        store = PasswordStore.read_from(args.password_store, args.master_password)
        store.save_to(args.password_store, args.password)

class PasswordActions:
    @staticmethod
    def print(pwd, account):
        print_err("Password for {}:".format(account))
        print(pwd)

    @staticmethod
    def clip(pwd, account):
        try:
            delay = 10
            xerox.copy(pwd, xsel=True)
            print_err("Password copied to clipboard for {}; clearing in {} seconds.".format(account, delay))
            sleep(delay)
        finally:
            xerox.copy("", xsel=True)
            print_err("Clipboard cleared.")

def add_subparser(subparsers, name, handler, default=None, **kwargs):
    subparser = subparsers.add_parser(name, **kwargs)
    subparser.add_argument("domain", nargs='?', default=default)
    subparser.add_argument("username", nargs='?', default=default)
    subparser.set_defaults(handler=handler)
    return subparser

def add_print_arg(subparser, default=PasswordActions.clip):
    subparser.add_argument("--print", action="store_const", dest="pw_action",
                           const=PasswordActions.print, default=default)

def add_overwrite_arg(subparser):
    subparser.add_argument("--overwrite", action="store_true",
                           help="Overwrite existing accounts without prompting.")

def add_gen_args(subparser):
    subparser.add_argument("--wordlist", default="/usr/share/dict/words")
    subparser.add_argument("--length", type=int, default=None)
    subparser.add_argument("--no-passphrase", action="store_true",
                           help="Generate a password instead of a passphrase.")
    subparser.add_argument("--simple", action="store_true",
                           help="Generate a short ascii-only string.")

def parse_args():
    parser = ArgumentParser(description='Generate, store, and retrieve passwords.')
    parser.add_argument("--password-store", help="Location of the password store [default: ~/.pwm].",
                        default=os.path.expanduser("~/.pwm"))
    parser.add_argument("--master-password", help="Master password")

    subparsers = parser.add_subparsers(help='Action', dest="action")

    get_parser = add_subparser(subparsers, "get", PasswordDriver.get,
                               help="Like `search', but copy password of shortest username to clipboard.")
    add_print_arg(get_parser)

    print_parser = add_subparser(subparsers, "print", PasswordDriver.print,
                               help="Like `get', but display password instead of copying.")

    exact_parser = add_subparser(subparsers, "exact", PasswordDriver.exact,
                                 help="Copy password of account matching search terms exactly to clipboard.")
    add_print_arg(exact_parser)

    search_parser = add_subparser(subparsers, "search", PasswordDriver.search,
                                  help="List accounts regexp-matching search terms.", aliases=['list'])
    add_print_arg(search_parser)

    put_parser = add_subparser(subparsers, "put", PasswordDriver.put,
                               help="Add a new record to the password store.")
    put_parser.add_argument("password", nargs='?', default=None)
    add_overwrite_arg(put_parser)

    pwsearch_parser = add_subparser(subparsers, "pwsearch", PasswordDriver.pwsearch,
                                       help="Find all accounts whose password matches a pattern.")

    delete_parser = add_subparser(subparsers, "delete", PasswordDriver.delete,
                                  help="Delete a record from the password store.")

    new_parser = add_subparser(subparsers, "new", PasswordDriver.new,
                               help="Like `put', but generate a random passphrase.")
    add_gen_args(new_parser)
    add_overwrite_arg(new_parser)
    add_print_arg(new_parser)

    gen_parser = add_subparser(subparsers, "gen", PasswordDriver.gen,
                               help="Like `new', but don't store the passphrase.")
    add_gen_args(gen_parser)
    gen_parser.set_defaults(needs_master=False)

    read_parser = add_subparser(subparsers, "read", PasswordDriver.read, help="Read records from standard input.")
    read_parser.add_argument("--file", default="-")
    add_overwrite_arg(read_parser)

    recode_parser = subparsers.add_parser("recode")
    recode_parser.add_argument("password", nargs='?', default=None)
    recode_parser.set_defaults(handler=PasswordDriver.recode)

    pwned_parser = subparsers.add_parser("pwned")
    pwned_parser.set_defaults(handler=PasswordDriver.pwned)

    args = parser.parse_args()
    if getattr(args, "needs_master", True):
        # Prompt needs to be recognized by emacs' comint-password-prompt-regexp
        args.master_password = query("Enter password for pwm store:", getpass, args.master_password)

    if not hasattr(args, "handler"):
        args.domain = None
        args.username = None
        args.handler = PasswordDriver.get
        args.pw_action = PasswordActions.clip
    return args

def run():
    try:
        args = parse_args()
        args.handler(args)
    except InvalidKeyException:
        print_err("Could not decrypt password database. Wrong key?")
