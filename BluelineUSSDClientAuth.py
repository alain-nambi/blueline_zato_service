# -*- coding: utf-8 -*-

"""
Copyright (C) November 2024 Blueline, Alain Nambinintsoa RAKOTOARIVELO
Licensed under LGPLv3.
"""

import json
import logging
from zato.server.service import Service
import redis
import requests
from requests.auth import HTTPBasicAuth
from six.moves.configparser import ConfigParser

# Load Configurations
CONFIG = ConfigParser()
CONFIG.read("/etc/auth_partner/auth_partner.conf")

# Redis Configuration
# db=4 by default
CONFIG_REDIS_DB = int(CONFIG.get('REDIS', 'AUTH_PARTNER_REDIS_DB', fallback=4))
REDIS_TOKEN_DB = redis.Redis(db=CONFIG_REDIS_DB)

# Authentication credentials
USERNAME = 'zato'
PASSWORD = 'qlnwFMKXqAe2soL7eYsx'

# Service name
BLUELINE_USSD_SERVICE_NAME = 'blueline.ussd.client.auth'


class BluelineUSSDClientAuth(Service):
    """
    Service class for handling USSD client authentication requests.
    """
    name = BLUELINE_USSD_SERVICE_NAME

    class SimpleIO:
        input_required = (
            "operator",
            "caller_num",
            "service_type",
            "login_type",
            "login",
        )
        input_optional = ("token",)
        default_value = "UNKNOWN"

    def handle_POST(self):
        # Retrieve token
        token = self._get_auth_token()
        if not token:
            return self._unauthorized_response(message='Missing or invalid token')

        # Check token in Redis
        redis_data = self._get_redis_token_data(token)
        if not redis_data:
            return self._unauthorized_response(message='Token not found in Redis')

        # Retrieve LDAP token
        ldap_token_data = self._get_ldap_token()
        if ldap_token_data is not None and 'status' in ldap_token_data:
            return self._error_response(
                status=ldap_token_data['status'],
                message=ldap_token_data['message']
            )

        # Perform USSD authentication
        ussd_response = self._authenticate_with_blueline(
            ldap_token=ldap_token_data['token'],
            operator=self.request.input.operator,
            caller_num=self.request.input.caller_num,
            service_type=self.request.input.service_type,
            login_type=self.request.input.login_type,
            login=self.request.input.login
        )

        # Process USSD process
        return self._process_ussd_response(ussd_response)
    def _get_auth_token(self):
        """
        Retrieve Bearer token from Auth header or return an error response.
        """
        http_auth = self.wsgi_environ.get('HTTP_AUTHORIZATION')
        # logging.info('HTTP Auth token : {}'.format(http_auth))

        if http_auth and http_auth.startswith('Bearer '):
            token = str(http_auth).split(' ', maxsplit=1)[1].strip()
            logging.info(
                '[BluelineUSSDClientAuth] [Retrieved Token]: {}\n'.format(
                    token
                )
            )
            return token

        self._error_response(status=401, message='Token not found')
        return None

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
            '[BluelineUSSDClientAuth] [Error Response]: {}\n'.format(
                self.response.payload
            )
        )

    def _unauthorized_response(self, message):
        """
        Return a 401 Unauthorized response with a given message
        """
        self.response.payload = {
            'ret_msg': message,
            'ret_code': 401,
            'ret_result': {}
        }
        self.response.status_code = 401
        logging.error("[BluelineUSSDClientAuth] [Authorization failed]: {}\n".format(
            self.response.payload))

    def _get_redis_token_data(self, token):
        """
        Retrieve token data from Redis.
        """
        redis_key = 'token:{}'.format(token)
        redis_data = REDIS_TOKEN_DB.hgetall(redis_key)
        logging.info(
            "[BluelineUSSDClientAuth] [Redis Token Data]: {}\n".format(redis_data))
        return redis_data

    def _get_ldap_token(self):
        """
        Retrieve LDAP token from USSD authentication.
        """
        try:
            response = self.invoke(
                'blueline.ldap.request.token',
                {
                    'username': USERNAME,
                    'password': PASSWORD
                }
            )

            # Securely extract the response's result
            ret_result = str(response['response']
                             ['ret_result']).replace("'", '"')

            # Attempt to load the response as JSON
            ldap_token = json.loads(ret_result)
            logging.info(
                "[BluelineUSSDClientAuth] [LDAP Token Retrieved]: {}\n".format(ldap_token))
            return ldap_token
        except Exception as ex:
            return self._error_response(
                status=500,
                message='Fetching LDAP Token failed: {}'.format(ex),
            )

    def _authenticate_with_blueline(self, ldap_token, operator, caller_num, service_type, login_type, login):
        """
        Perform authentication with Blueline USSD API.
        """
        url = 'https://api.blueline.mg/staging/ussd/v1/clients/authenticate'
        headers = {'Content-Type': 'application/json'}
        params = {
            'operator': operator,
            'caller_num': caller_num,
            'service_type': service_type,
            'login_type': login_type,
            'login': login,
        }
        
        try:
            response = requests.post(
                url=url,
                headers=headers,
                data=json.dumps(params),
                auth=HTTPBasicAuth(username=ldap_token, password=''),
                timeout=60
            )
            
            response.raise_for_status()
            logging.info('[BluelineUSSDClientAuth] [Blueline USSD API]: {}\n'.format(response.json()))
            
            return response.json()
        except requests.exceptions.Timeout:
            logging.error(
                '[BluelineUSSDClientAuth] [Timeout Error] : Request timed out\n'
            )
            self._error_response(
                status=504,
                message='Request timed out for API USSD Auth Request\n'
            )
        except requests.exceptions.RequestException as ex:
            logging.error(
                '[BluelineUSSDClientAuth] [RequestException Error] : {}\n'.format(ex)
            )
            self._error_response(
                status=500,
                message=str(ex)
            )

    def _process_ussd_response(self, ussd_response):
        """
        Process the response from USSD authentication
        """
        status = ussd_response.get('status', 500)
        ret_result = None
        ret_msg = None
        if status == 200:
            ret_result = json.loads(str(ussd_response['message']).replace("'", '"'))
            ret_msg = ussd_response.get('info', 'Success')
        else:
            ret_result = {'info': ussd_response.get('message')}
            ret_msg = ussd_response.get('error', 'Error')
        
        self.response.payload = {
            'ret_msg': ret_msg,
            'ret_code': status,
            'ret_result': ret_result
        }
        self.response.status_code = status
        logging.info('[BluelineUSSDClientAuth] [Final Response]: {}\n'.format(self.response.payload))
        return status