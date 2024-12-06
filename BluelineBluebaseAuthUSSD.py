import json
import logging
from zato.server.service import Service
from six.moves.configparser import ConfigParser
import xmltodict
import redis

CONFIG = ConfigParser()
CONFIG.read("/etc/auth_partner/auth_partner.conf")

BLUELINE_BLUEBASE_AUTH_USSD = 'blueline.bluebase.auth.ussd'

# Redis Configuration
CONFIG_REDIS_DB = int(CONFIG.get('REDIS', 'AUTH_PARTNER_REDIS_DB', fallback=4))
REDIS_TOKEN_DB = redis.Redis(db=CONFIG_REDIS_DB)


class BluelineBluebaseAuthUSSD(Service):
    """
    Service class for handling USSD authentication via SOAP API.
    """
    name = BLUELINE_BLUEBASE_AUTH_USSD

    class SimpleIO:
        input_required = (
            "operator",
            "caller_num",
            "service_type",
            "login_type",
            "login",
        )
        default_value = 'UNKNOWN'

    def handle(self):
        # Extract input parameters
        operator = self.request.input.operator
        caller_num = self.request.input.caller_num
        service_type = self.request.input.service_type
        login_type = self.request.input.login_type
        login = self.request.input.login
        
        token = self.request.payload['token']
        logging.info(f'[Blueline Bluebase Auth USSD] [Token Received] {token}')

        if not token:
            return self._unauthorized_response(message='Unauthorized : Token not found')

        # Construct authentication payload
        auth_payload = self._create_auth_payload(operator, caller_num, service_type, login_type, login)

        logging.info(f'[Blueline Bluebase Auth USSD] Payload sent for "auth_ussd": {auth_payload}')

        # Send the SOAP request
        response = self._send_soap_request(auth_payload)

        if response:
            return self._process_response(response, caller_num, operator, login)
        else:
            return self._unauthorized_response(message='Failed to get response from SOAP service')

    def _create_auth_payload(self, operator, caller_num, service_type, login_type, login):
        """
        Create the authentication payload for the SOAP request.
        """
        return {
            "root": {
                "header": {
                    "version": "1",
                    "param1": "auth_ussd",
                    "ident": CONFIG['BLUEBASE']['ident'],
                    "psw": CONFIG['BLUEBASE']['pswd'],
                },
                "data": {
                    'operator': operator,
                    'caller_num': caller_num,
                    'service_type': service_type,
                    'type_auth': login_type,
                    'login_auth': str(login),
                },
            }
        }

    def _send_soap_request(self, auth_payload):
        """
        Send the SOAP request and return the response.
        """
        with self.outgoing.soap.get("BluelineBluebaseS4DService").conn.client() as client:
            logging.info(f"Payload sent for 'auth_ussd': {auth_payload}")
            data_xml = xmltodict.unparse(auth_payload)
            logging.info(f"Payload XML sent: {data_xml}")

            try:
                return client.service.S4D(data_xml)
            except Exception as e:
                logging.error(f"Error during SOAP request: {e}")
                return None

    def _process_response(self, response, caller_num, operator, login):
        """
        Process the SOAP response and construct the response payload.
        """
        try:
            # Parse the XML reponse and log it
            response_dict = xmltodict.parse(response)
            response_json = json.dumps(response_dict, indent=4)
            logging.info(f"Response in JSON: {response_json}")

            # Extract response data
            response_data = response_dict.get("root", {}).get("data", {})
            logging.error(f'Response Data: {response_data}')
            
            # Check for errors in the response
            error_message = response_data.get("error")
            if error_message:
                error_num = response_data.get("error_num", None)
                self.response.payload = {
                    'ret_msg': error_message,
                    'error_num': error_num,
                    'ret_code': 401,
                    'ret_result': {}
                }
                self.response.status_code = 401
                
                return self.response.payload

            device_name = self._extract_device_name(response_data, login)

            response_payload = {
                "ret_msg": "Authentication successful ;)",
                "ret_code": 200,
                "data": {
                    "caller_num": caller_num,
                    "customer_id": response_data.get("client_refnum"),
                    "device_name": [device_name],
                    "last_name": response_data.get("client_prenom"),
                    "name": response_data.get("client_nom"),
                    "num_is_mine": response_data.get("num_is_mine"),
                    "operator": operator,
                },
            }

            logging.info(f"Response payload: {response_payload}")
            self.response.payload = response_payload
            return response_payload

        except Exception as e:
            logging.error(f"Error during processing response: {e}")
            return self._unauthorized_response(message='Error processing response')

    def _extract_device_name(self, response_data, login):
        """
        Extract the device name from the response data.
        """
        device_ids = response_data.get("device_id", [])
        if isinstance(device_ids, list) and device_ids:
            try:
                return device_ids[device_ids.index(login)]
            except ValueError:
                return None
        return None

    def _unauthorized_response(self, message):
        """
        Return a 401 Unauthorized response with a given message.
        """
        self.response.payload = {
            'ret_msg': message,
            'ret_code': 401,
            'ret_result': {}
        }
        self.response.status_code = 401
        logging.error(f"[BluelineBluebaseAuthUSSD] [Authorization failed]: {self.response.payload}")
    
    def _error_response(self, status, message):
        """
        Set an error response with a custom status code and message.
        """
        self.response.payload = {
            'ret_msg': message,
            'ret_code': status,
            'ret_result': {}
        }
        self.response.status_code = status
        logging.error(f'[BluelineBluebaseAuthUSSD] [Error Response]: {self.response.payload}')
