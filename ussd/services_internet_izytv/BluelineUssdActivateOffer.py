# -*- coding: utf-8 -*-

"""
Copyright (C) Aug 2024 Blueline, Henintsoa Moriaa
Licensed under LGPLv3.

Updated by Alain Nambii on 12 Feb 2025
"""

# Standard library
import base64
import json
import logging
import redis, re, requests
from requests.auth import HTTPBasicAuth
from six.moves.configparser import ConfigParser
from json import dumps, loads
from zato.common import DATA_FORMAT
from zato.server.service import Service
from datetime import datetime
import uuid

REDIS_CHECK = redis.Redis(db=8)

# Load configuration from config file
CONFIG = ConfigParser()
CONFIG.read([
    "/etc/auth_partner/auth_partner.conf",
    "/etc/ussd-services/ussd-services.conf"
])


# Redis configuration
# REDIS_SERVER = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_SERVER")
# REDIS_PORT = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_PORT")
# REDIS_TOKEN_DB = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_DB")

REDIS_TOKEN_DB = redis.Redis(db=4)


# Constants variables
USERNAME = 'zato'
PASSWORD = 'qlnwFMKXqAe2soL7eYsx'
BLUELINE_SERVICE_NAME = 'blueline.ussd.activate.offer'
LDAP_SERVICE_NAME = 'blueline.ldap.request.token'
LDAP_AUTH = {'username': USERNAME, 'password': PASSWORD}


class BluelineUssdActivateOffer(Service):
    name = BLUELINE_SERVICE_NAME

    class SimpleIO:
        input_required = (
            'operator', 'caller_num', 'service_type',
            'device_name', 'amount', 'offer_id', 
            'offer_name', 'customer_id'
        )
        input_optional = ('balance', 'reference1', 'reference2')
        # output_required = ('ret_code', 'ret_msg', 'ret_result')
        default_value = 'UNKNOWN'


    def _create_log(self, message, logging_type):
        """Log a message with a border for better visibility."""
        border_length = max(len(message) + 6, 75)
        border = '-' * border_length

        log_methods = {
            "warning": logging.warning,
            "error": logging.error,
            "info": logging.info
        }

        # Default to info if logging_type is not recognized
        log_method = log_methods.get(logging_type, logging.info)
        log_method(f"\n{border}\n  {message}  \n{border}")


    def _extract_inputs(self):
        """Extract and return input data from request"""
        return {
            'operator': self.request.input.operator,
            'caller_num': self.request.input.caller_num,
            'service_type': self.request.input.service_type,
            'device_name': self.request.input.device_name,
            'amount': self.request.input.amount,
            'offer_id': self.request.input.offer_id,
            'offer_name': self.request.input.offer_name,
            'customer_id': self.request.input.customer_id,
            'balance': self.request.input.balance,
            'reference1': self.request.input.reference1,
            'reference2': self.request.input.reference2,
        }
    
    
    def _validate_token(self):
        """Validate the token from the request header."""
        wsgi = self.wsgi_environ
        http_auth = wsgi.get('HTTP_AUTHORIZATION', '')
        if not http_auth or not http_auth.startswith('Bearer '):
            return False, "Unauthorized"
        
        token = http_auth.split(' ')[1].strip()
        token_value = REDIS_TOKEN_DB.hgetall(f'token:{token}')
        
        if not token_value:
            return False, "Unauthorized _ wrong token"
        
        return True, f"Token valid for {token}"


    def _get_ldap_token(self):
        """Invoke LDAP token request"""
        call_response = self.invoke(
            LDAP_SERVICE_NAME,
            LDAP_AUTH,
        )
        ldap_token = json.loads(str(call_response['response']['ret_result']).replace("'", '"'))
        return ldap_token


    def _activate_offer(self, inputs, ldap_token):
        """Activate the offer using the provided inputs and LDAP token"""
        ussd_login = ldap_token['token']
        request_id = str(uuid.uuid4())
        
        params = {
            'operator': inputs.get('operator'),
            'caller_num': inputs.get('caller_num'),
            'service_type': inputs.get('service_type'),
            'device_name': inputs.get('device_name', ''),
            'amount': inputs.get('amount', 0),
            'offer_id': inputs.get('offer_id'),
            'offer_name': inputs.get('offer_name', 'default_bundle_name'),
            'request_id': request_id,
            'balance': inputs.get('balance', 0),
            'reference1': inputs.get('reference1'),
            'reference2': inputs.get('reference2'),
            'partner_ref': inputs.get('partner_ref', request_id)
        }
        
        # Adjust device name for internet service type
        if params["service_type"] == "internet":
            if len(params["device_name"]) != 12 or params["device_name"].startswith("261"):
                params["device_name"] = params["device_name"][-9:]
        
        activation_data = {
            "client_refnum": inputs.get("customer_id"),
            "customer_id": inputs.get("customer_id"),
            "offre_refnum": params["offer_id"],
            "amount": params["amount"],
            "balance": params["balance"],
            "device_id": params["device_name"],
            "caller_num": params["caller_num"],
            "operator": params["operator"],
            "offer_ref": params["offer_id"],
            "service_type": params["service_type"],
            "token": ussd_login,
            "transaction_date": self.get_datetime_now(),
            "request_id": params["request_id"],
            "bundle_name": params["offer_name"],
            "reference1": params.get("reference1"),
            "reference2": params.get("reference2"),
            "partner_ref": params["partner_ref"] if params["operator"] != "bip" else request_id,
        }
        
        # Store in Redis if not 'bip'
        if activation_data['operator'] != 'bip':
            activation_data['headers'] = str(activation_data.get('headers', {}))
            activation_data = {k: (v if v is not None else 'Default_None') for k, v in activation_data.items()}
            REDIS_CHECK.hmset(activation_data["partner_ref"], activation_data)
        
        result = {
            "data": activation_data,
            "status": 200,
            "info": "ack",
            "message": "traitement en cours",
        }
        
        logging.info(result)
        
        # def process(self, message):
        #     connection = pika.BlockingConnection(
        #         pika.ConnectionParameters(host="localhost", virtual_host="/ussd")
        #     )
        #     channel = connection.channel()
        #     channel.exchange_declare(exchange="ussd_offer", exchange_type="topic")
        #     channel.basic_publish(
        #         routing_key="ussd_msg",
        #         exchange="ussd_offer",
        #         properties=pika.BasicProperties(
        #             app_id="ussd-services", delivery_mode=2  # rendre le message persistant
        #         ),
        #         body=message,
        #     )
        #     connection.close()
        
        # Send to RabbitMQ
        # self.process(json.dumps(result))
        
        url_status = CONFIG["APP"].get("url_status_airtel" if params["operator"] == "airtel" else "url_status")
        details = (f"{url_status}/ussd/v1/clients/{params['operator']}/{params['request_id']}" 
                   if activation_data["operator"] != "bip" else "resultat envoyé via sms")
        
        response = {
            "status": result["status"],
            "info": "traitement en cours",
            "message": details,
            "code": "040-05-200",
        }
        
        self._handle_response(response)
    
    @staticmethod
    def get_datetime_now():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

     
    def _handle_response(self, response):
        """Handle the response from the offer activation request."""
        # dict_response = json.loads(response.text) or response
        dict_response = response
        ret_code = dict_response['status']
        ret_msg = dict_response['info'] if ret_code == 200 else dict_response['error']
        ret_result = dict_response['message']

        if ret_code == 200:
            ret_result = {
                'request_ref': str(ret_result).split('/')[-1],
                'operator': str(ret_result).split('/')[-2]
            }

        self._log_and_respond(ret_code, ret_msg, ret_result)

  
    def handle_POST(self):
        """ Activate Offer """        
        ######################
        # Extract input data #
        ######################
        inputs = self._extract_inputs()
        
        self._create_log(
            message=f'1. Extract input data \n {inputs}',
            logging_type='info',
        )
        
        ##################
        # Validate token #
        ##################
        self._create_log(
            message=f'2. Validate token',
            logging_type='info',
        )
        
        token_valid, token_message = self._validate_token()
        if not token_valid:
            self._log_and_respond(
                ret_code=401,
                ret_msg='Unauthorized',
                ret_result=token_message
            )
            return
        
        ##################
        # Get LDAP token #
        ##################
        self._create_log(
            message=f'3. Get LDAP token',
            logging_type='info',
        )
        
        ldap_token = self._get_ldap_token()
        if 'status' in ldap_token:
            self._log_and_respond(
                ret_code=ldap_token['status'],
                ret_msg=ldap_token['error'],
                ret_result=ldap_token
            )
            return
        
        ##################
        # Activate offer #
        ##################
        self._create_log(
            message=f'4. Activate offer',
            logging_type='info',
        )
        self._activate_offer(inputs, ldap_token)


    def _log_and_respond(self, ret_code, ret_msg, ret_result):
        """Log the response and send it back to the client."""
        self.response.payload = {
            'ret_msg': ret_msg,
            'ret_code': ret_code,
            'ret_result': ret_result
        }
        
        self._create_log(
            message=f'[FINAL RESPONSE] [{BLUELINE_SERVICE_NAME}] \n{self.response.payload}',
            logging_type='warning',
        )
        
        self.response.status_code = ret_code
        self.logger.info(f'[{BLUELINE_SERVICE_NAME}] {ret_msg}')
        self.log_output(BLUELINE_SERVICE_NAME)