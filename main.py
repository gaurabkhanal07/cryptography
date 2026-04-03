# main.py
from colorama import init, Fore, Style
from pyfiglet import Figlet
from cipher import run as caesar_run

init(autoreset=True)  # Colorama setup

def print_banner():
    f = Figlet(font='slant')
    print(Fore.RED + f.renderText('CRYPTO TOOL'))

def main():
    print_banner()
    
    while True:
        print(Fore.CYAN + "\n=== MAIN MENU ===")
        print(Fore.YELLOW + "1. Caesar Cipher")
        print(Fore.YELLOW + "2. Exit")
        
        choice = input(Fore.GREEN + "Select an option: ").strip()
        
        if choice == "1":
            caesar_run()
        elif choice == "2":
            print(Fore.MAGENTA + "Exiting... Stay safe, hacker! 🕶️")
            break
        else:
            print(Fore.RED + "Invalid option! Try again.")

if __name__ == "__main__":
    main()