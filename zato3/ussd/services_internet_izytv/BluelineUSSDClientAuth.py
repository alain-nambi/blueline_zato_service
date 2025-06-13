# -*- coding: utf-8 -*-

"""
Copyright (C) November 2024 Blueline, Alain Nambinintsoa RAKOTOARIVELO
Licensed under LGPLv3.

This module handles USSD client authentication requests for the Blueline service.
It manages token validation, LDAP authentication, and USSD service communication.
"""

import json
import logging
from typing import Dict, Optional, Any, Union
from zato.server.service import Service
import redis
from six.moves.configparser import ConfigParser
from zato.common import DATA_FORMAT

# Configure logging
logger = logging.getLogger(__name__)

# Configuration Constants
CONFIG_PATH = "/etc/auth_partner/auth_partner.conf"
AUTH_HEADER_PREFIX = 'Bearer '
REDIS_TOKEN_PREFIX = 'token:'

# Load Configurations
CONFIG = ConfigParser()
CONFIG.read(CONFIG_PATH)

# Redis Configuration
CONFIG_REDIS_DB = int(CONFIG.get('REDIS', 'AUTH_PARTNER_REDIS_DB', fallback=4))
REDIS_TOKEN_DB = redis.Redis(db=CONFIG_REDIS_DB)

# Authentication credentials
USERNAME = 'zato'
PASSWORD = 'qlnwFMKXqAe2soL7eYsx'

# Service names
BLUELINE_USSD_SERVICE_NAME = 'blueline.ussd.client.auth'
BLUELINE_BLUEBASE_AUTH_USSD = 'blueline.bluebase.auth.ussd'
BLUELINE_LDAP_REQUEST_TOKEN = 'blueline.ldap.request.token'

class BluelineUSSDClientAuth(Service):
    """
    Service class for handling USSD client authentication requests.
    
    This service manages the complete authentication flow:
    1. Validates incoming Bearer token
    2. Retrieves token data from Redis
    3. Obtains LDAP token
    4. Authenticates with Blueline USSD API
    5. Processes and returns the response
    """
    name = BLUELINE_USSD_SERVICE_NAME

    class SimpleIO:
        """Defines the input/output structure for the service."""
        input_required = (
            "operator",
            "caller_num",
            "service_type",
            "login_type",
            "login",
        )
        input_optional = ("token",)
        default_value = "UNKNOWN"

    def handle_POST(self) -> None:
        """
        Handles POST requests for USSD client authentication.
        
        Returns:
            None: Sets the response payload and status code
        """
        # Validate authentication token
        token = self._get_auth_token()
        if not token:
            return self._unauthorized_response(message='Missing or invalid token')

        # Get token data from Redis
        redis_data = self._get_redis_token_data(token)
        if not redis_data:
            return self._unauthorized_response(message='Token not found in Redis')

        # Get LDAP token
        ldap_token_data = self._get_ldap_token()
        if isinstance(ldap_token_data, dict) and 'status' in ldap_token_data:
            return self._error_response(
                status=ldap_token_data['status'],
                message=ldap_token_data['message']
            )

        # Authenticate with Blueline
        ussd_response = self._authenticate_with_blueline(
            ldap_token=ldap_token_data['token'],
            operator=self.request.input.operator,
            caller_num=self.request.input.caller_num,
            service_type=self.request.input.service_type,
            login_type=self.request.input.login_type,
            login=self.request.input.login
        )

        logger.info('USSD Response received: %s', ussd_response)
        return self._process_ussd_response(ussd_response)

    def _get_auth_token(self) -> Optional[str]:
        """
        Retrieves Bearer token from Authorization header.
        
        Returns:
            Optional[str]: The token if found, None otherwise
        """
        http_auth = self.wsgi_environ.get('HTTP_AUTHORIZATION')
        if http_auth and http_auth.startswith(AUTH_HEADER_PREFIX):
            token = http_auth.split(' ', maxsplit=1)[1].strip()
            logger.debug('Retrieved token: %s', token)
            return token
        return None

    def _error_response(self, status: int, message: str) -> None:
        """
        Sets an error response with custom status code and message.
        
        Args:
            status (int): HTTP status code
            message (str): Error message
        """
        self.response.payload = {
            'ret_msg': message,
            'ret_code': status,
            'ret_result': {}
        }
        self.response.status_code = status
        logger.error('Error response: %s', self.response.payload)

    def _unauthorized_response(self, message: str) -> None:
        """
        Returns a 401 Unauthorized response.
        
        Args:
            message (str): Unauthorized message
        """
        return self._error_response(401, message)

    def _get_redis_token_data(self, token: str) -> Dict[str, Any]:
        """
        Retrieves token data from Redis.
        
        Args:
            token (str): The token to look up
            
        Returns:
            Dict[str, Any]: Token data from Redis
        """
        redis_key = f'{REDIS_TOKEN_PREFIX}{token}'
        redis_data = REDIS_TOKEN_DB.hgetall(redis_key)
        logger.debug('Redis token data: %s', redis_data)
        return redis_data

    def _get_ldap_token(self) -> Union[Dict[str, Any], None]:
        """
        Retrieves LDAP token from USSD authentication service.
        
        Returns:
            Union[Dict[str, Any], None]: LDAP token data or error response
        """
        try:
            response = self.invoke(
                BLUELINE_LDAP_REQUEST_TOKEN,
                {
                    'username': USERNAME,
                    'password': PASSWORD
                }
            )
            ret_result = str(response['response']['ret_result']).replace("'", '"')
            ldap_token = json.loads(ret_result)
            logger.debug('LDAP token retrieved: %s', ldap_token)
            return ldap_token
        except Exception as ex:
            logger.error('Failed to fetch LDAP token: %s', ex)
            return self._error_response(
                status=500,
                message=f'Fetching LDAP Token failed: {ex}'
            )

    def _authenticate_with_blueline(
        self,
        ldap_token: str,
        operator: str,
        caller_num: str,
        service_type: str,
        login_type: str,
        login: str
    ) -> Dict[str, Any]:
        """
        Performs authentication with Blueline USSD API.
        
        Args:
            ldap_token (str): LDAP authentication token
            operator (str): Operator identifier
            caller_num (str): Caller's phone number
            service_type (str): Type of service
            login_type (str): Type of login
            login (str): Login credentials
            
        Returns:
            Dict[str, Any]: Response from Blueline USSD API
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
            response = self.invoke(
                BLUELINE_BLUEBASE_AUTH_USSD,
                params,
                data_format=DATA_FORMAT.JSON
            )
            logger.debug('Blueline USSD API response: %s', response)
            return response
        except Exception as ex:
            logger.error('Bluebase Auth error: %s', ex)
            return self._error_response(status=500, message=str(ex))

    def _process_ussd_response(self, ussd_response: Optional[Dict[str, Any]]) -> None:
        """
        Processes the response from USSD authentication.
        
        Args:
            ussd_response (Optional[Dict[str, Any]]): Response from USSD service
        """
        if ussd_response is None:
            logger.error('USSD response is None')
            self._error_response(500, 'USSD response is None')
            return

        # Extract response components
        ret_code = ussd_response.get('ret_code', 500)
        ret_result = ussd_response.get('data', {})
        ret_msg = ussd_response.get('ret_msg')
        error_num = ussd_response.get('error_num')

        # Build response payload
        self.response.payload = {
            'ret_msg': ret_msg,
            'ret_code': ret_code,
            'ret_result': ret_result
        }
        
        if error_num:
            self.response.payload['error_num'] = error_num
        
        self.response.status_code = ret_code
        logger.info('Final response: %s', self.response.payload)