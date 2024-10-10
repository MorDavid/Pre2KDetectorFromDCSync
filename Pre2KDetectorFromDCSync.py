import argparse
import hashlib

class Pre2KAccountFinder:
    def __init__(self, file_path):
        self.file_path = file_path
        self.machine_accounts = []

    def generate_credentials(self, account_name):
        account_name_lower = account_name.lower()  # Convert account name to lowercase

        if len(account_name) >= 15:
            # If account name is 15 characters or more, use the first 14 characters
            password = account_name_lower[:14]
        else:
            # If account name is less than 15 characters, use the entire name minus the last character
            password = account_name_lower[:-1]

        return f"{account_name}:{password}"

    def get_nt_hash(self, password):
        # Convert password to bytes (UTF-16LE encoding)
        password_bytes = password.encode('utf-16le')
        
        # Generate NT hash using MD4
        nt_hash = hashlib.new('md4', password_bytes).digest()
        
        # Return the hash in hexadecimal format
        return nt_hash.hex().upper()

    def read_secretsdump(self):
        try:
            with open(self.file_path, 'r') as file:
                for line in file:
                    parts = line.split(':')
                    if len(parts) > 2:  # Ensure there are enough parts to extract the account name and hash
                        account_name = parts[0]
                        nt_hash = parts[2]
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

        for account_name, stored_nt_hash in self.machine_accounts:
            # Generate the potential password for comparison
            potential_password = account_name[:-1].lower()  # Assume password is the account name without '$' in lowercase
            computed_nt_hash = self.get_nt_hash(potential_password)

            if computed_nt_hash == stored_nt_hash.upper():
                print(f"Found Pre2k account: {account_name} with hash: {stored_nt_hash} matches potential password: {potential_password}")

def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Find Pre-Windows 2000 accounts from secretsdump output.')
    parser.add_argument('-f', '--file', required=True, help='Path to the secretsdump output file')
    
    args = parser.parse_args()
    
    # Instantiate the Pre2KAccountFinder class and find accounts
    finder = Pre2KAccountFinder(args.file)
    finder.find_pre2k_accounts()

if __name__ == '__main__':
    main()
