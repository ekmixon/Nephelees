import argparse


class Logger:
    def __init__(self, verbosity=0, quiet=False):
        self.verbosity = verbosity
        self.quiet = quiet

    def debug(self, message):
        if self.verbosity == 2:
            print(f"{YELLOW}[DEBUG]{END} {message}")

    def verbose(self, message):
        if self.verbosity >= 1:
            print(f"{BLUE}[VERBOSE]{END} {message}")

    def info(self, message):
        if not self.quiet:
            print(f"{BOLD_BLUE}[*]{END} {message}")

    def success(self, message):
        if not self.quiet:
            print(f"{BOLD_GREEN}[+]{END} {message}")

    def warning(self, message):
        if not self.quiet:
            print(f"{BOLD_ORANGE}[-]{END} {message}")

    def error(self, message):
        if not self.quiet:
            print(f"{BOLD_RED}[!]{END} {message}")


def get_options():
    description = "Turn your hashcat formatted hashes files into anonymized files for offline but online cracking (" \
                  "i.e. Google Colab for example) "
    epilog = ""

    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("-ntds", "--ntds", dest="ntds_path", action="store",
                        help="hashcat format ntds file to crack", required=False)
    parser.add_argument("-asreproast", "--asreproast", dest="asreproast_path", action="store",
                        help="hashcat format asreproast file to crack", required=False)
    parser.add_argument("-kerberoast", "--kerberoast", dest="kerberoast_path", action="store",
                        help="hashcat format kerberoast file to crack", required=False)
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="count",
        default=0,
        help="verbosity level (-v for verbose, -vv for debug)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="show no information at all",
    )

    return parser.parse_args()


def ntds_anonymize(file_path):
    logger.info(f"Anonymizing ntds file {file_path}")
    with open(file_path, "r") as clear_file:
        with open(f"{file_path}_hashanon", "w") as anone_file:
            for increment, hash in enumerate(clear_file):
                username = hash.strip().split(":")[0]
                new_hash = hash.split(":")[1:]
                new_hash.insert(0, f"user{str(increment)}")
                logger.debug(new_hash)
                anone_file.write(":".join(new_hash))
        logger.success(f"Done writing to file {file_path}_hashanon")


def asreproast_anonymize(file_path):
    logger.info(f"Anonymizing ASREProast file {file_path}")
    with open(file_path, "r") as clear_file:
        with open(f"{file_path}_hashanon", "w") as anone_file:
            for increment, hash in enumerate(clear_file):
                new_hash = hash.split("$")[:3]
                checksum = hash.split("$")[3].split(":")[1]
                new_hash.append(f"user{str(increment)}:{checksum}")
                new_hash += hash.split("$")[4:]
                logger.debug(new_hash)
                anone_file.write("$".join(new_hash))
        logger.success(f"Done writing to file {file_path}_hashanon")


def kerberoast_anonymize(file_path):
    logger.info(f"Anonymizing Kerberoast file {file_path}")
    with open(file_path, "r") as clear_file:
        with open(f"{file_path}_hashanon", "w") as anone_file:
            for increment, hash in enumerate(clear_file):
                new_hash = hash.split("$")[:3]
                new_hash.append(f"*user{str(increment)}$domain$some/spn*")
                new_hash += hash.split("$")[6:]
                logger.debug(new_hash)
                anone_file.write("$".join(new_hash))
        logger.success(f"Done writing to file {file_path}_hashanon")


def main():
    if options.ntds_path:
        ntds_anonymize(options.ntds_path)
    if options.asreproast_path:
        asreproast_anonymize(options.asreproast_path)
    if options.kerberoast_path:
        kerberoast_anonymize(options.kerberoast_path)


if __name__ == "__main__":
    BOLD_GREEN = "\033[1;32m"
    BOLD_BLUE = "\033[1;34m"
    BOLD_WHITE = "\033[1;37m"
    BOLD_RED = "\033[1;31m"
    BOLD_ORANGE = "\033[1;93m"
    END = "\033[0m"
    BLUE = "\033[0;34m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    RED = "\033[0;31m"

    options = get_options()
    logger = Logger(options.verbosity, options.quiet)

    main()
