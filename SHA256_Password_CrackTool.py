from pwn import *
import sys
import hashlib

if len(sys.argv) != 3:
    print("Invalid arguments")
    print(f"Usage: {sys.argv[0]} <sha256sum> <wordlist_path>")
    sys.exit(1)

target_hash = sys.argv[1]
wordlist_path = sys.argv[2]
attempt_counter = 0

try:
    with open(wordlist_path, "r", encoding="latin-1") as wordlist:
        with log.progress(f"Attempting to crack {target_hash}") as progress_log:
            for password in wordlist:
                password = password.strip("\n").encode("latin-1")
                candidate_hash = hashlib.sha256(password).hexdigest()

                print(f"Trying: {password.decode('latin-1')} -> {candidate_hash}") 

                if candidate_hash == target_hash:
                    progress_log.success(
                        f"[{attempt_counter}] attempts: {password.decode('latin-1')} == {candidate_hash}"
                    )
                    break 

                attempt_counter += 1
            else:
                progress_log.failure(f"Password not found after {attempt_counter} attempts.")
                sys.exit(1)  


    sys.exit(0)

except FileNotFoundError:
    print(f"Error: The file '{wordlist_path}' was not found. Please check the path and try again.")
    sys.exit(1)

    




