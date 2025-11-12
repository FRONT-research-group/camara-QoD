import os
from opencapif_sdk import capif_invoker_connector,service_discoverer


INVOKER_CONFIG_FILE = os.getenv('INVOKER_CONFIG_FILE', './src/app/invoker_onboarding/invoker_config_sample.json')

def onboard_invoker() -> str:
    """
    Onboards an invoker to the CAPIF system, discovers available services, retrieves a JWT access token, 
    prints it, and writes it to a file.
    This function performs the following steps:
    1. Initializes the CAPIF invoker connector using the provided configuration file.
    2. Onboards the invoker to the CAPIF system.
    3. Initializes the service discoverer using the same configuration file.
    4. Discovers available services.
    5. Retrieves JWT tokens from the service discoverer.
    6. Prints the obtained JWT token.
    7. Writes the JWT token to a specified access token file.

    Raises:
        Any exceptions raised by the underlying connector or file operations.
    """

    capif_connector = capif_invoker_connector(config_file=INVOKER_CONFIG_FILE)

    capif_connector.onboard_invoker()

    discoverer_svc = service_discoverer(config_file=INVOKER_CONFIG_FILE)
    discoverer_svc.discover()


    discoverer_svc.get_tokens()
    jwt_token=discoverer_svc.token

    return jwt_token
