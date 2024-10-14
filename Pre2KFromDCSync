import argparse
import time
from Crypto.Hash import MD4
from tabulate import tabulate

class Pre2KAccountFinder:
    def __init__(self, file_path, output_file):
        self.file_path = file_path
        self.output_file = output_file
        self.machine_accounts = []

    def get_nt_hash(self, password):
        # Convert password to bytes (UTF-16LE encoding)
        password_bytes = password.encode('utf-16le')

        # Generate NT hash using MD4 from pycryptodome
        hasher = MD4.new()
        hasher.update(password_bytes)
        nt_hash = hasher.digest()

        # Return the hash in hexadecimal format
        return nt_hash.hex().upper()

    def read_secretsdump(self):
        try:
            with open(self.file_path, 'r') as file:
                for line in file:
                    parts = line.split(':')
                    if len(parts) > 2:  # Ensure there are enough parts to extract the account name and hash
                        account_name = parts[0]
                        nt_hash = parts[3]
                        if account_name.endswith('$'):  # Check for machine accounts
                            self.machine_accounts.append((account_name, nt_hash))
        except FileNotFoundError:
            print(f"The file {self.file_path} was not found.")
            return []

    def find_pre2k_accounts(self):
        self.read_secretsdump()
        
        if not self.machine_accounts:
            print("No machine accounts found.")
            return
        
        results = []  # Store results for output
        found_count = 0  # Counter for found accounts
        
        for account_name, stored_nt_hash in self.machine_accounts:
            # Generate the potential password for comparison
            trimmed_account_name = account_name[:14]  # Only take the first 14 characters
            potential_password = trimmed_account_name.rstrip('$').lower()  # Remove '$' and convert to lowercase
            computed_nt_hash = self.get_nt_hash(potential_password)

            if computed_nt_hash == stored_nt_hash.upper():
                # Append the found account info to results
                results.append([account_name, stored_nt_hash, potential_password])
                found_count += 1  # Increment the counter for found accounts

        # Print results in a table format
        if results:
            print(tabulate(results, headers=["Account Name", "Stored NT Hash", "Potential Password"], tablefmt="simple_grid"))
        
        # Write results to output file if specified
        if self.output_file:
            with open(self.output_file, 'w') as out_file:
                out_file.write("Account Name,Stored NT Hash,Potential Password\n")
                for row in results:
                    out_file.write(",".join(row) + "\n")
            print(f"\nResults saved to {self.output_file}")

        # Print the count of found accounts
        print(f"\nTotal Pre2K accounts found: {found_count}")

def main():
    print("""
 █▀█ █▀▄ █▀▀   ▀▀▄   █ █   █▀▄ █▀▀ █▀▀ █ █ █▀█ █▀▀
 █▀▀ █▀▄ █▀▀   ▄▀    █▀▄   █ █ █   ▀▀█  █  █ █ █  
 ▀   ▀ ▀ ▀▀▀   ▀▀▀   ▀ ▀   ▀▀  ▀▀▀ ▀▀▀  ▀  ▀ ▀ ▀▀▀
                                      By Mor David

The Pre2KDCSync script is a Python utility designed to identify potential Pre-Windows 2000 (Pre2K) machine accounts by analyzing the output from the secretsdump tool.
This script leverages NT hashes derived from the machine account names to check for accounts that use similar passwords, a common practice in Windows environments prior to Windows 2000.
""")
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Find Pre-Windows 2000 accounts from secretsdump output.')
    parser.add_argument('-f', '--file', required=True, help='Path to the secretsdump output file')
    parser.add_argument('-o', '--output', help='Path to the output file for results')

    args = parser.parse_args()
    
    # Start timing
    start_time = time.time()
    
    # Instantiate the Pre2KAccountFinder class and find accounts
    finder = Pre2KAccountFinder(args.file, args.output)
    finder.find_pre2k_accounts()
    
    # End timing
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # Print the elapsed time
    print(f"\nExecution time: {elapsed_time:.2f} seconds")

if __name__ == '__main__':
    main()
