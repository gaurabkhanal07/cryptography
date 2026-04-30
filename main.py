# main.py
from colorama import Fore, init
from pyfiglet import Figlet
from crypto_toolkit import run as crypto_run

init(autoreset=True)

def print_banner() -> None:
    figlet = Figlet(font="slant")
    print(Fore.RED + figlet.renderText("CRYPTO TOOL"))

def main() -> None:
    print_banner()
    crypto_run()

if __name__ == "__main__":
    main()