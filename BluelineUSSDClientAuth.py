# -*- coding: utf-8 -*-

"""
Copyright (C) November 2024 Blueline, Alain Nambinintsoa RAKOTOARIVELO
Licensed under LGPLv3.
"""

import json
import logging
from zato.server.service import Service
import redis
from six.moves.configparser import ConfigParser
from zato.common import DATA_FORMAT

# Load Configurations
CONFIG = ConfigParser()
CONFIG.read("/etc/auth_partner/auth_partner.conf")

# Redis Configuration
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
        token = self._get_auth_token()
        if not token:
            return self._unauthorized_response(message='Missing or invalid token')

        redis_data = self._get_redis_token_data(token)
        if not redis_data:
            return self._unauthorized_response(message='Token not found in Redis')

        ldap_token_data = self._get_ldap_token()
        if ldap_token_data and 'status' in ldap_token_data:
            return self._error_response(
                status=ldap_token_data['status'],
                message=ldap_token_data['message']
            )

        ussd_response = self._authenticate_with_blueline(
            ldap_token=ldap_token_data['token'],
            operator=self.request.input.operator,
            caller_num=self.request.input.caller_num,
            service_type=self.request.input.service_type,
            login_type=self.request.input.login_type,
            login=self.request.input.login
        )

        logging.info(f'[BluelineUSSDClientAuth] [USSD Response]: {ussd_response}')
        return self._process_ussd_response(ussd_response)

    def _get_auth_token(self):
        """
        Retrieve Bearer token from Auth header or return an error response.
        """
        http_auth = self.wsgi_environ.get('HTTP_AUTHORIZATION')
        if http_auth and http_auth.startswith('Bearer '):
            token = http_auth.split(' ', maxsplit=1)[1].strip()
            logging.info(f'[BluelineUSSDClientAuth] [Retrieved Token]: {token}')
            return token

        return self._error_response(status=401, message='Token not found')

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
        logging.error(f'[BluelineUSSDClientAuth] [Error Response]: {self.response.payload}')

    def _unauthorized_response(self, message):
        """
        Return a 401 Unauthorized response with a given message
        """
        return self._error_response(401, message)

    def _get_redis_token_data(self, token):
        """
        Retrieve token data from Redis.
        """
        redis_key = f'token:{token}'
        redis_data = REDIS_TOKEN_DB.hgetall(redis_key)
        logging.info(f"[BluelineUSSDClientAuth] [Redis Token Data]: {redis_data}")
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
            ret_result = str(response['response']['ret_result']).replace("'", '"')
            ldap_token = json.loads(ret_result)
            logging.info(f"[BluelineUSSDClientAuth] [LDAP Token Retrieved]: {ldap_token}")
            return ldap_token
        except Exception as ex:
            return self._error_response(
                status=500,
                message=f'Fetching LDAP Token failed: {ex}'
            )

    def _authenticate_with_blueline(self, ldap_token, operator, caller_num, service_type, login_type, login):
        """
        Perform authentication with Blueline USSD API.
        """
        params = {
            'token': ldap_token,
            'operator': operator,
            'caller_num': caller_num,
            'service_type': service_type,
            'login_type': login_type,
            'login': login,
        }

        try:
            BLUELINE_BLUEBASE_AUTH_USSD = 'blueline.bluebase.auth.ussd'
            response = self.invoke(BLUELINE_BLUEBASE_AUTH_USSD, params, data_format=DATA_FORMAT.JSON)
            logging.info(f'[BluelineUSSDClientAuth] [Blueline USSD API]: {response}')
            return response
        except Exception as ex:
            logging.error(f'[BluelineUSSDClientAuth] [Bluebase Auth] : ERROR: {ex}')
            return self._error_response(status=500, message=str(ex))

    def _process_ussd_response(self, ussd_response):
        """
        Process the response from USSD authentication.
        """
        
        # Check if ussd_response is None
        if ussd_response is None:
            logging.error('USSD response is None. Returning error response.')
            self.response.payload = {
                'ret_msg': 'USSD response is None',
                'ret_code': 500,
                'ret_result': {}
            }
            self.response.status_code = 500
            return

        logging.info(f"USSD FINAL RESPONSE : {ussd_response}")

        # Extract ret_code and ensure it's an integer
        ret_code = ussd_response.get('ret_code', 500)
        ret_result = ussd_response.get('data', {})
        ret_msg = ussd_response.get('ret_msg', None)
        error_num = ussd_response.get('error_num', None)

        self.response.payload = {
            'ret_msg': ret_msg,
            'ret_code': ret_code,
            'ret_result': ret_result
        }
        
        if error_num:
            self.response.payload['error_num'] = error_num
        
        self.response.status_code = ret_code
        logging.info(f'[BluelineUSSDClientAuth] [Final Response]: {self.response.payload}')