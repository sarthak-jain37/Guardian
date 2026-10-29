"""Create a private archive key registry; prints its path, never key material."""
import argparse
import json
import os
from pathlib import Path
from cryptography.fernet import Fernet


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path',type=Path)
    args=parser.parse_args()
    args.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(args.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as output:
        json.dump({'active':'key-1','keys':{'key-1':Fernet.generate_key().decode()}},output)
        output.flush();os.fsync(output.fileno())
    print(str(args.path.resolve()))


if __name__=='__main__':main()
