import requests
import os

green = '\033[92m'
red = '\033[91m'
reset = '\033[0m'


def check_xss_vulnerability(url, payload_list):
    try:
        response = requests.get(url)
        xss_protection = response.headers.get('X-XSS-Protection', '')

        if xss_protection and xss_protection.lower() == '1; mode=block':
            print(f"XSS Protection is {green}OFF{reset}")
        else:
            print(f"XSS Protection is {red}ON{reset}")
            print("Exiting the program.")
            return

        with open(payload_list, 'r') as file:
            payloads = [line.strip() for line in file if line.strip()]  # Skip empty lines

        for payload in payloads:
            # Splitting URL into base URL and parameters
            base_url, params = url.split('?', 1) if '?' in url else (url, '')
            params_dict = dict(p.split('=') for p in params.split('&')) if params else {}

            for param, value in params_dict.items():
                # Injecting payload into each parameter
                params_dict[param] = f"{value}{payload}"

                # Constructing the modified URL
                modified_url = base_url + '?' + '&'.join(f"{k}={v}" for k, v in params_dict.items())

                # Sending request and checking for payload reflection
                response = requests.get(modified_url)
                if payload in response.text:
                    print(
                        f"{green}[+]{reset} This URL '{url}' is {red}vulnerable{reset} to XSS with payload: {red}{payload}{reset}")
                else:
                    print(
                        f"{red}[-]{reset} This URL '{url}' is not vulnerable to XSS with payload: {payload}")

    except FileNotFoundError:
        print("Payload List File not found.")
    except requests.RequestException as e:
        print("An Error Occurred:", e)


def get_user_input(prompt):
    while True:
        user_input = input(prompt)
        if user_input.strip():
            return user_input.strip()
        else:
            print("Please provide a non-empty input.")
            
def scan_urls_from_file(file_path, payload_list):
    try:
        with open(file_path, 'r') as urls_file:
            urls = [line.strip() for line in urls_file if line.strip()]  # Skip empty lines

        for url in urls:
            print("\n--- XSS Vulnerability Checker ---")
            print(f"Checking URL: {url}")
            check_xss_vulnerability(url, payload_list)
    except FileNotFoundError:
        print("URLs File not found.")
    except Exception as e:
        print("An Error Occurred:", e)           


if __name__ == "__main__":
    while True:
        print("-----------------------------------")
        print("--- XSS Vulnerability Checker ---")
        print("-----------------------------------")
        print("Select an option:")
        print("-----------------------------------")
        print("1. Check a particular URL")
        print("2. Check URLs from a file")
        option = input("Enter your choice (1 or 2): ").strip()

        if option == '1':
            target_URL = input("Enter the target URL: ")
            payload_list = input("Enter the path for the Payload List file: ")
            if os.path.exists(payload_list):
                check_xss_vulnerability(target_URL, payload_list)
            else:
                print("Invalid Path. Please Provide a Valid Path for the Payload List.")
                
            choice = input("Do you want to check another URL? (yes/no): ").strip().lower()    
            if choice == 'no':
             new_payload_list_choice = get_user_input("Do you want to enter a new Payload List file? (yes/no): ")
             if new_payload_list_choice == 'yes':
                  new_payload_list = get_user_input("Enter the path for the new Payload List file: ")
                  if os.path.exists(new_payload_list):
                        print("Payload List File Selected:", new_payload_list)
                        payload_list = new_payload_list
                        check_xss_vulnerability(target_URL, payload_list)
             else:
                    print("Invalid Path. Continuing with the previous Payload List.")     
                
        elif option == '2':
            file_path = input("Enter the path for the file containing URLs to scan: ")
            payload_list = input("Enter the path for the Payload List file: ")
            if os.path.exists(file_path) and os.path.exists(payload_list):
                scan_urls_from_file(file_path, payload_list)
            else:
                print("Invalid Path. Please Provide Valid Paths for the URL file and Payload List.")
                
            choice = input("Do you want to check another option? (yes/no): ").strip().lower()    
            if choice == 'no':
                new_payload_list_choice = get_user_input("Do you want to enter a new Payload List file? (yes/no): ")
                if new_payload_list_choice == 'yes':
                    new_payload_list = get_user_input("Enter the path for the new Payload List file: ")
                    if os.path.exists(new_payload_list):
                        print("Payload List File Selected:", new_payload_list)
                        payload_list = new_payload_list
                        scan_urls_from_file(file_path, payload_list)
                else:
                    print("Continuing with the previous Payload List.")      
                
        else:
            print("Invalid option. Please enter 1 or 2.")

        if choice != 'yes':
            print("Exiting the program.")
            break
