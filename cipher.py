SHIFT = 3  # Fixed shift


def encrypt(text):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + SHIFT) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result


def decrypt(text):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset - SHIFT) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result


def banner():
    print("""
============================
   CAESAR CIPHER TOOL
     (SHIFT = 3)
============================
""")


def main():
    banner()

    # 🔹 Initial input
    text = input("Enter your text: ")

    while True:
        print("\nWhat do you want to do?")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Change Text")
        print("4. Exit")

        choice = input("Enter choice (1/2/3/4): ")

        if choice == "1":
            text = encrypt(text)
            print("[+] Encrypted:", text)

        elif choice == "2":
            text = decrypt(text)
            print("[+] Decrypted:", text)

        elif choice == "3":
            text = input("Enter new text: ")

        elif choice == "4":
            print("Exiting tool...")
            break

        else:
            print("[-] Invalid choice!")


if __name__ == "__main__":
    main()