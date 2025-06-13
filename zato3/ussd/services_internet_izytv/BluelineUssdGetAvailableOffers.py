# -*- coding: utf-8 -*-

"""
Copyright (C) Aug 2024 Blueline, Henintsoa Moriaa
Licensed under LGPLv3.

@Updated by Alain on 19 Feb 2025
"""

# stdlib
import base64
import json
import logging
import redis
import re
import requests
from requests.auth import HTTPBasicAuth
from six.moves.configparser import ConfigParser
from zato.common import DATA_FORMAT
from zato.server.service import Service

import xmltodict

CONFIG = ConfigParser()
CONFIG.read([
    "/etc/auth_partner/auth_partner.conf",
    "/etc/ussd-services/ussd-services.conf"
])

REDIS_TOKEN_DB = redis.Redis(db=4)
USERNAME = 'zato'
PASSWORD = 'qlnwFMKXqAe2soL7eYsx'
blueline_service_name = 'blueline.ussd.get.available.offers'

class BluelineUssdGetAvailableOffers(Service):
    name = blueline_service_name

    class SimpleIO:
        input_required = (
            'operator', 'caller_num', 'service_type',
            'device_name', 'customer_id', 
        )
        default_value = 'UNKNOWN'

    def _create_log(self, message, logging_type):
        """Log a message with a border for better visibility."""
        border_length = min(len(message) + 6, 75)
        border = '-' * border_length

        log_methods = {
            "warning": logging.warning,
            "error": logging.error,
            "info": logging.info
        }

        log_method = log_methods.get(logging_type, logging.info)
        log_method(f"\n{border}\n  {message}  \n{border}")

    def _validate_authentication(self, wsgi):
        """Validate the Bearer token in the request."""
        http_auth = wsgi.get('HTTP_AUTHORIZATION')
        if not http_auth or not http_auth.startswith('Bearer '):
            self._create_log("Unauthorized: Missing or invalid Bearer token", "error")
            return False, None
        return True, http_auth.split(' ')[1]

    def _validate_token(self, token):
        """Validate the token against Redis."""
        redis_key = f'token:{token.strip()}'
        token_value = REDIS_TOKEN_DB.hgetall(redis_key)
        self._create_log(f"Redis token check - Key:{redis_key} Value:{token_value}", "debug")
        return bool(token_value)

    def _get_ldap_token(self):
        """Acquire LDAP token."""
        ldap_response = self.invoke(
            'blueline.ldap.request.token',
            {'username': USERNAME, 'password': PASSWORD},
        )
        ldap_token = json.loads(str(ldap_response['response']['ret_result']).replace("'", '"'))
        if 'status' in ldap_token:
            error_msg = f"LDAP error - Status:{ldap_token['status']} Error:{ldap_token['error']}"
            self._create_log(error_msg, "error")
            return None, ldap_token['status'], ldap_token['error']
        return ldap_token['token'], None, None

    def _call_ussd_api(self, ussd_login, params, customer_id):
        """Call the USSD API to fetch available offers."""
        headers = {"Content-Type": "application/json"}
        url = f'https://api.blueline.mg/staging/ussd/v1/clients/{customer_id}/offers'
        try:
            response = requests.get(
                url,
                json=params,
                auth=HTTPBasicAuth(ussd_login, ''),
                headers=headers,
                timeout=25
            )
            self._create_log(f"API response - Status:{response.status_code} Body:{response.text}", "debug")
            return response, None
        except requests.exceptions.Timeout:
            self._create_log("Timeout occurred while fetching offers from USSD service", "error")
            return None, (504, 'Read timed out (USSD Services)')
        except Exception as e:
            self._create_log(f"Unexpected error during API call: {str(e)}", "error")
            return None, (500, 'Internal Server Error (USSD Services)')

    def _process_api_response(self, response):
        """Process the API response and extract relevant data."""
        try:
            response_data = response.json()
            ret_code = response_data.get('status', 500)
            ret_msg = response_data.get('info') or response_data.get('error', 'Unknown error')
            ret_result = response_data.get('message')
            return ret_code, ret_msg, ret_result
        except json.JSONDecodeError:
            self._create_log("Invalid JSON response from USSD service", "error")
            return 500, 'Invalid response format', None

    def _build_response(self, code, message, result):
        """Helper to construct standardized response."""
        self.response.payload = {
            'ret_code': code,
            'ret_msg': message,
            'ret_result': result
        }
        self.response.status_code = code
        
        # Log the final response
        self._create_log(f"[{blueline_service_name}] Final Response - Result:{result}", "info")
        
        return self.response

    def handle_GET(self):
        """Handle GET requests for available USSD offers."""
        operator = self.request.input.operator
        caller_num = self.request.input.caller_num
        service_type = self.request.input.service_type
        device_name = self.request.input.device_name
        customer_id = self.request.input.customer_id

        # Initial request logging
        wsgi = self.wsgi_environ
        self._create_log(f"WSGI request environment: {wsgi}", "info")

        # Step 1: Validate authentication
        self._create_log("Step 1: Validate authentication", "info")
        is_authenticated, token = self._validate_authentication(wsgi)
        if not is_authenticated:
            return self._build_response(401, 'Unauthorized', None)

        # Step 2: Validate token
        self._create_log("Step 2: Validate token", "info")
        if not self._validate_token(token):
            return self._build_response(401, 'Unauthorized', None)

        # Step 3: Get LDAP token
        self._create_log("Step 3: Get LDAP token", "info")
        ussd_login, ldap_error_code, ldap_error_msg = self._get_ldap_token()
        if ldap_error_code:
            return self._build_response(ldap_error_code, ldap_error_msg, None)

        # Step 4: Prepare API parameters
        self._create_log("Step 4: Prepare API parameters", "info")
        params = {
            'operator': operator,
            'caller_num': caller_num,
            'service_type': service_type,
            'device_name': device_name
        }
        
        # Step 5: Call Bluebase API
        
        """
        <?xml version="1.0" encoding="UTF-8" standalone="no" ?>

        <root>
            <header>
                <version>1</version>
                <param1>ussd_get_recharge</param1>
                <param2/>
                <param3/>
                <ident>....</ident>
                <psw>........</psw>
            </header>
            <data>
                <session>(texte)</session>
                <operator>(texte)</operator>
                <caller_num>(texte)</caller_num>
                <service_type>(texte)</service_type>
                <client_refnum>(entier)</client_refnum>
                <device_id>(texte)</device_id>
                <solde>(entier)</solde>
                <jour>(texte)</jour>
                <bouquet>(texte)</bouquet> 
            </data>
        </root>
        """
        
        def format_phonenumber(service_type, device_id):
            if service_type == "internet":
                if device_id.startswith("261") or len(device_id) != 12:
                    device_id = device_id[-9:]
            return device_id
        
        soap_payload = {
            "root": {
                "header": {
                    "version": "1",
                    "param1": "ussd_get_recharge",
                    "ident": CONFIG['BLUEBASE']['ident'],
                    "psw": CONFIG['BLUEBASE']['pswd'],
                },
                "data": {
                    'operator': operator,
                    'caller_num': caller_num,
                    'service_type': service_type,
                    'client_refnum': customer_id,
                    'device_id': format_phonenumber(service_type, device_name),
                    'solde': CONFIG["MISC"]["default_balance"]
                },
            }
        }
        
        with self.outgoing.soap.get("BluelineBluebaseS4DService").conn.client() as client:
            data_xml = xmltodict.unparse(soap_payload)
            self._create_log("SOAP Request - Payload: %s" % data_xml, "info")
            
            try:
                response = client.service.S4D(data_xml)
                response_dict = xmltodict.parse(response)
                # self._create_log("SOAP Response - Body: %s" % response_dict, "info")
                
                bluebase_data = response_dict.get('root', {}).get('data', {})
                self._create_log("Bluebase data - %s" % bluebase_data, "info")
                
                if bluebase_data:
                    offers = bluebase_data.get('offre')
                    if not isinstance(offers, list):
                        offers = [offers]
                    offers = [
                        {
                            "name": offer.get('intitule'),
                            "price": offer.get('price'),
                            "offer_id": offer.get('refnum')
                        }
                        for offer in offers
                    ]
                    
                    # Initialize the result object
                    result = {
                        "length": len(offers),
                        "service_type": service_type,
                        "offers": offers,
                    }
                    
                    self._build_response(
                        code=200,
                        message='Get Offers OK ;)',
                        result=result
                    )
            except Exception as exc:
                self._create_log("Error while calling Bluebase API - %s" % str(exc), "error")
                return self._build_response(500, 'Internal Server Error (Bluebase)', str(exc))
                

        # # Step 5: Call USSD API
        # self._create_log("Step 5: Call USSD API", "info")
        # response, api_error = self._call_ussd_api(ussd_login, params, customer_id)
        # if api_error:
        #     return self._build_response(*api_error, None)

        # # Step 6: Process API response
        # self._create_log("Step 6: Process API response", "info")
        # ret_code, ret_msg, ret_result = self._process_api_response(response)

        # # Step 7: Log and return final response
        # log_message = 'get available offers - successful' if ret_code == 200 else 'get available offers - failed'
        # self._create_log(log_message, "info")
        # return self._build_response(ret_code, ret_msg, ret_result)