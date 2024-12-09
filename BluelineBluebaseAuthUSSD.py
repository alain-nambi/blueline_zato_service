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

"""
[MISC]
blntv_tana_type = Decouverte,Magique,Ultime 
blntv_province_type = Vision,Magique,Passion
bip_offer_type = Forfait voix,Forfait mixte,Forfait Internet,Forfait sms
#validity_option_tv = 30,90
validity_option_tv = 30
;Internet Days Validity
validity_option_internet = 7,30,90
; 4G Prepaid/ LTE
pcode_1147 = 30,90
pcode_1044 = 30,90
; 3G/4G Silver
pcode_other = 2,7,30
partner_credit_limit = 200
; solde par defaut pour la recuperation
; des offres disponibles sur 4D
default_balance = 1000000
"""

CONFIG_DATA = {
    'MISC': {
        'validity_option_tv': 30,
        'validity_option_internet': [7, 30, 90],
        'default_balance': 1000000,
        'blntv_tana_type': 'Decouverte,Magique,Ultime',
        'blntv_province_type': 'Vision,Magique,Passion',
        'pcode_1147': '30,90',
        'pcode_1044': '30,90',
        'pcode_other': '2,7,30',
    }

}


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
        auth_payload = self._create_auth_payload(
            operator,
            caller_num,
            service_type,
            login_type,
            login
        )

        logging.info(f'[Blueline Bluebase Auth USSD] Payload sent for "auth_ussd": {auth_payload}')

        # Send the SOAP request
        response = self._send_soap_request(auth_payload)

        if response:
            return self._process_response(response, caller_num, operator, login, service_type)
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
            # logging.info(f"Payload sent for 'auth_ussd': {auth_payload}")
            data_xml = xmltodict.unparse(auth_payload)
            # logging.info(f"Payload XML sent: {data_xml}")

            try:
                return client.service.S4D(data_xml)
            except Exception as error:
                logging.error(f"[Blueline Bluebase Auth USSD] [Error during SOAP request]: {error}")

                self.invoke(
                    "blueline.send.email",
                    {
                        'mail_to': "nambinintsoa.rakotoarivelo@staff.blueline.mg",  # dev@si.blueline.mg
                        'mail_from': "zato3dev@si.blueline.mg",
                        'mail_text': f"Error during SOAP request or response processing: {error}",
                        'title': "[BluelineUssdGetClientInvoice] USSD Authentication | Error",
                    },
                    as_bunch=True,
                )
                logging.info("Error report sent by email to dev@si.blueline.mg")

                return None

    def _user_bouquet(self, area):
        if area == "Tana":
            bouquet_type = CONFIG_DATA["MISC"]["blntv_tana_type"]
        if area == "Province":
            bouquet_type = CONFIG_DATA["MISC"]["blntv_province_type"]
        return bouquet_type

    def _process_response(self, response, caller_num, operator, login, service_type):
        """
        Process the SOAP response and construct the response payload.
        """
        
        logging.info(f"[Blueline Bluebase Auth USSD] [Process the SOAP response and construct the response payload]")
        
        try:
            # Parse the XML reponse and log it
            response_dict = xmltodict.parse(response)
            # logging.info(f"Response in JSON: {json.dumps(response_dict, indent=4)}")

            # Extract response data
            bluebase_data = response_dict.get("root", {}).get("data", {})
            # logging.info(f'Response Data: {bluebase_data}')

            # Check for errors in the response
            error_message = bluebase_data.get("error")
            if error_message:
                self.response.payload = {
                    'ret_msg': error_message,
                    'error_num': bluebase_data.get("error_num", None),
                    'ret_code': 401,
                    'ret_result': {}
                }
                self.response.status_code = 401
                return self.response.payload

            # Initialize variables
            monbouquet = {}
            days = {}
            product_code = {}

            # Check if phone number is mine
            if str(caller_num).startswith('03900') or str(caller_num).startswith('3900'):
                bluebase_data['num_is_mine'] = "Vrai"

            # Extracet device name and IDS
            device_name = self._extract_device_name(bluebase_data, login)
            device_ids = bluebase_data.get("device_id", [])

            # Initialize return response
            result = {
                "ret_msg": "Authentication successful ;)",
                "ret_code": 200,
                "data": {
                    "caller_num": caller_num,
                    "customer_id": bluebase_data.get("client_refnum"),
                    "device_name": device_name or list({device for device in device_ids if device is not None}) if device_ids else None,
                    "last_name": bluebase_data.get("client_prenom") or "-",
                    "name": bluebase_data.get("client_nom") or "-",
                    "num_is_mine": bluebase_data.get("num_is_mine"),
                    "operator": operator,
                },
            }

            # Extract unique durations
            def extract_unique_durations(offers):
                unique_durations = set()
                for offer in offers:
                    try:
                        duration = int(offer["duree"].replace(" jours", "").replace(" jour", ""))
                        unique_durations.add(duration)
                    except ValueError:
                        logging.warning(f"Invalid duration format: {offer['duree']}")
                return sorted(unique_durations)

            # Check if service type is tv
            if service_type in ['tv']:
                result["data"]["jour"] = CONFIG_DATA["MISC"][f'validity_option_{service_type}']

            day_list_str = None

            # Check if service type is internet
            if service_type in ["internet"]:
                # Get recharge data (offre)
                offers_ussd_get_recharge = self._handle_get_recharge(
                    result=result,
                    service_type=service_type
                )["offre"]

                unique_durations = extract_unique_durations(offers=offers_ussd_get_recharge)
                day_list_str = ", ".join(map(str, unique_durations))

                # logging.info(f'day_list_str : {day_list_str} {type(day_list_str)}')

            # Check if device_id in bluebase data
            if "device_id" in bluebase_data and bluebase_data["device_id"] is not None:
                device_ids = bluebase_data["device_id"]
                logging.info(f"[Blueline Bluebase Auth USSD] [Device IDS]: {device_ids}")

                # Handle case where device_id is a single string
                if isinstance(bluebase_data["device_id"], str):
                    result["data"]["device_name"] = [login] if login in ["internet_num", "tv_card_num"] else [device_ids]
                    if service_type == "tv":
                        area = bluebase_data["device_ville"]
                        bouquet = self._user_bouquet(area=area)
                        monbouquet[device_ids] = bouquet
                        result["data"]["bouquet"] = monbouquet
                    elif service_type == "internet":
                        result["data"]["product_code"] = bluebase_data["device_pcode"]
                        p_code = f'p_code_{result["data"]["product_code"]}'
                        result["data"]["jour"] = CONFIG_DATA["MISC"].get(p_code, day_list_str)

                else:
                    # Handle case where device_id is a list
                    if login in device_ids:
                        device = login
                        my_device_idx = bluebase_data["device_id"].index(device)
                        result["data"]["device_name"] = [device]

                        # Process service type for TV
                        if service_type == "tv":
                            area = bluebase_data["device_ville"][my_device_idx]
                            bouquet = self._user_bouquet(area=area)
                            monbouquet[device] = bouquet
                            result["data"]['bouquet'] = monbouquet
                        
                        # Process service type for Internet
                        elif service_type == "internet":
                            product_code[device] = bluebase_data["device_pcode"][my_device_idx]
                            result["data"]["product_code"] = product_code[device]
                            p_code = f"pcode_{result['data']['product_code']}"
                            result["data"]["jour"] = CONFIG_DATA["MISC"].get(p_code, day_list_str)
                    
                    else:
                        # Handle case if operator is Airtel
                        devices = device_ids[:3] if operator == "airtel" else device_ids
                        for device in devices:
                            my_device_idx = device_ids.index(device)
                            result["data"]["device_name"].append(device)
                            # Process service type for TV
                            if service_type == "tv":
                                area = bluebase_data["device_ville"][my_device_idx]
                                bouquet = self._user_bouquet(area=area)
                                monbouquet[device] = bouquet
                                result["data"]["bouquet"] = monbouquet
                            
                            # Process service type for Internet
                            elif service_type == "internet":
                                device_pcode = bluebase_data["device_pcode"][my_device_idx]
                                product_code[device] = device_pcode
                                p_code = f"pcode_{device_pcode}"
                                days[device] = CONFIG_DATA["MISC"].get(p_code, day_list_str)
                                result["data"]["jour"] = days
                            result["data"]["product_code"] = product_code
            self.response.payload = result
            return result

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
        logging.error(
            f"[BluelineBluebaseAuthUSSD] [Authorization failed]: {self.response.payload}")

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
        logging.error(
            f'[BluelineBluebaseAuthUSSD] [Error Response]: {self.response.payload}')

    def _handle_get_recharge(self, result, service_type):
        data_for_ussd_get_recharge = {
            "operator": result["data"]["operator"],
            "caller_num": result["data"]["caller_num"],
            "client_refnum": result["data"]["customer_id"],
            "service_type": service_type,
            "device_id": result["data"]["device_name"],
            "solde": CONFIG_DATA["MISC"]["default_balance"]
        }

        ussd_get_recharge_request = {
            "root": {
                "header": {
                    "version": "1",
                    "param1": "ussd_get_recharge",
                    "ident": CONFIG['BLUEBASE']['ident'],
                    "psw": CONFIG['BLUEBASE']['pswd'],
                },
                "data": data_for_ussd_get_recharge
            }
        }

        recharge_response = self._send_soap_request(ussd_get_recharge_request)
        recharge_data = xmltodict.parse(
            recharge_response
        ).get("root", {}).get("data", {})
        logging.info(
            f"[BluelineBluebaseAuthUSSD] [Recharge Response Data]: {recharge_data}")

        return recharge_data
