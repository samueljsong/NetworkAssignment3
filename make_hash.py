#!/usr/bin/env python3
import argparse
import bcrypt as pybcrypt
from passlib.hash import sha512_crypt, sha256_crypt, md5_crypt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-s", "--salt", default="salt123")
    parser.add_argument("-r", "--rounds", type=int, default=10)
    args = parser.parse_args()

    pw = args.password
    salt = args.salt

    print("\n=== Generated shadow-style hashes ===\n")

    print("MD5 ($1$):")
    print(md5_crypt.using(salt=salt).hash(pw))
    print()

    print("SHA256 ($5$):")
    print(sha256_crypt.using(salt=salt).hash(pw))
    print()

    print("SHA512 ($6$):")
    print(sha512_crypt.using(salt=salt).hash(pw))
    print()

    pw_bytes = pw.encode("utf-8")
    if len(pw_bytes) > 72:
        pw_bytes = pw_bytes[:72]

    print("bcrypt ($2b$):")
    b_hash = pybcrypt.hashpw(pw_bytes, pybcrypt.gensalt(rounds=args.rounds))
    print(b_hash.decode("utf-8"))
    print()

    print("NOTE: yescrypt ($y$) is best generated on Linux (mkpasswd -m yescrypt).")

if __name__ == "__main__":
    main()
