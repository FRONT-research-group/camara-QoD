import json
import os
import logging
import requests
import urllib3
from requests.auth import HTTPBasicAuth
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    level=logging.INFO,  # Minimum severity level to log
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Log message format
    handlers=[
        logging.FileHandler("logs/register_logs.log"),  # Log to a file
        logging.StreamHandler()  # Also display in the console
    ]
)

logger = logging.getLogger("CAPIF Register")

def main():
    """
    Main function to register and log in a user using CAPIF SDK.

    This function performs the following steps:
    1. Loads configuration variables from a JSON file.
    2. Logs in to CAPIF and retrieves an access token.
    3. Creates a new user with the obtained access token and configuration variables.
    4. Logs the UUID of the newly created user.

    Raises:
        KeyError: If expected keys are missing in the results from CAPIF operations.
        Exception: For any errors during the registration and login process.
    """
    variables = __load_config_file(config_file="./capif_sdk_register.json")
    log_result = __log_to_capif(variables)
    admintoken = log_result["access_token"]
    postcreation = __create_user(admintoken, variables)
    uuid = postcreation["uuid"]
    logger.info(uuid)

def __log_to_capif(variables):
    logger.info("Logging in to CAPIF")
    capif_register_url = "https://" + variables["register_host"].strip() + ":" + variables["capif_register_port"] + "/"
    try:
        url = capif_register_url + "login"

        response = requests.request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            auth=HTTPBasicAuth(variables["capif_register_username"], variables["capif_register_password"]),
            verify=False,
            timeout=10
        )
        response.raise_for_status()
        response_payload = json.loads(response.text)
        logger.info("Logged in to CAPIF successfully and obtained the following response_payload: %s", response_payload)
        return response_payload
    except Exception as e:
        logger.error("Error during login to CAPIF: %s",e)
        raise

def __create_user(admin_token, variables):
    logger.info("Creating user in CAPIF")
    capif_register_url = "https://" + variables["register_host"].strip() + ":" + variables["capif_register_port"] + "/"
    try:
        url = capif_register_url + "createUser"
        payload = {
            "username": variables["capif_username"],
            "password": variables["capif_password"],
            "description": "description",
            "email": "csr_email_address@dimokritos.gr",
            "enterprise": "csr_organization",
            "country": "csr_locality",
            "purpose": "test SDK user",
        }
        headers = {
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        }

        response = requests.request(
            "POST", url, headers=headers, data=json.dumps(payload), verify=False, timeout=10
        )
        response.raise_for_status()
        response_payload = json.loads(response.text)
        logger.info("User created successfully with the following response_payload: %s", response_payload)
        return response_payload
    except Exception as e:
        logger.error("Error during user creation in CAPIF: %s",e)
        raise

def __load_config_file(config_file: str):
    """Load the configuration file."""
    try:
        with open(config_file, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.warning("Configuration file %s not found. Using defaults or environment variables.",config_file)
        return {}

if __name__ == "__main__":
    logger.info("Initializing CAPIF Register")
    main()
