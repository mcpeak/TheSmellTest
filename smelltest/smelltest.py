import argparse
import os

import core.utils as utils

from core.YaraHandler import YaraHandler

def main():
    parser = argparse.ArgumentParser(
        description='Bandit - a Python source code security analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', metavar='targets', type=str, nargs='+',
        help='target directory(s) to scan')

    args = parser.parse_args()

    yh = YaraHandler()

    for target in args.targets:
        for f in utils.discover_files(target):
            if os.path.isfile(f.path):
                #print("Scanning: ", f.path)
                matches = yh.match_file(f.path)
                if matches and len(matches) > 0:
                    for match in matches:
                        _, _, result = match.strings[0]
                        print("\n\n", result, "\n\n")

if __name__ == "__main__":
    main()
