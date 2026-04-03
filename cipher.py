# caesar_cipher.py
from colorama import Fore

def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) - 65 + shift) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            result += char
    return result

def decrypt(text, shift):
    return encrypt(text, -shift)

def run():
    print(Fore.CYAN + "\n=== Caesar Cipher ===")
    choice = input(Fore.GREEN + "Do you want to (E)ncrypt or (D)ecrypt? ").strip().lower()
    text = input(Fore.GREEN + "Enter the text: ")
    shift = int(input(Fore.GREEN + "Enter the shift key (number): "))
    
    if choice == "e":
        print(Fore.YELLOW + "Encrypted Text: " + Fore.MAGENTA + encrypt(text, shift))
    elif choice == "d":
        print(Fore.YELLOW + "Decrypted Text: " + Fore.MAGENTA + decrypt(text, shift))
    else:
        print(Fore.RED + "Invalid choice!")