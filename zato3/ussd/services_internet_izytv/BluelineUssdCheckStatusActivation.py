# -*- coding: utf-8 -*-
"""
Copyright (C) May 2025 Blueline, Alain Nambinintsoa
Licensed under LGPLv3.

USSD Subscription Service - Handles retrieval of mobile subscriptions through USSD gateway.
"""

from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional
import json
import logging
import redis
from requests.auth import HTTPBasicAuth
from six.moves.configparser import ConfigParser
from zato.server.service import Service

# Configuration
CONFIG = ConfigParser()
CONFIG.read("/etc/auth_partner/auth_partner.conf")

# Redis Databases
REDIS_TOKEN_DB = redis.Redis(db=4)
REDIS_USSD_DB = redis.Redis(db=8)

# Constants
USERNAME = 'zato'
PASSWORD = 'qlnwFMKXqAe2soL7eYsx'
BLUELINE_SERVICE_NAME = 'blueline.ussd.check.status.activation'
SERVICE_LDAP = 'blueline.ldap.request.token'
LDAP_AUTH = {'username': USERNAME, 'password': PASSWORD}

@dataclass
class ServiceResponse:
    """Data class to hold service response data"""
    ret_code: int
    ret_msg: str
    ret_result: Optional[Dict[str, Any]] = None

class BluelineUssdCheckStatusActivation(Service):
    """Service to check USSD activation status with improved error handling and performance"""
    
    name = BLUELINE_SERVICE_NAME

    class SimpleIO:
        input_required = ('request_ref', 'operator')
        # output_required = ('ret_code', 'ret_msg', 'ret_result')
        default_value = 'UNKNOWN'
        
    def _create_log(self, message: str, logging_type: str = 'info') -> None:
        """Create formatted log messages with borders
        
        Args:
            message: The message to log
            logging_type: Type of logging (info, warning, error)
        """
        border = "-" * (min(75, len(message) + 6))
        log_func = getattr(logging, logging_type)
        log_func(f"\n{border}\n  {message}  \n{border}")
    
    def _validate_token(self) -> Tuple[bool, str]:
        """Validate the token from the request header.
        
        Returns:
            Tuple containing (is_valid, message)
        """
        wsgi = self.wsgi_environ
        http_auth = wsgi.get('HTTP_AUTHORIZATION', '')
        
        if not http_auth or not http_auth.startswith('Bearer '):
            return False, "Unauthorized"
        
        token = http_auth.split(' ')[1].strip()
        token_value = REDIS_TOKEN_DB.hgetall(f'token:{token}')
        
        if not token_value:
            return False, "Unauthorized - wrong token"
        
        return True, f"Token valid for {token}"
        
    def _parse_redis_data(self, redis_data: Dict[bytes, bytes]) -> Dict[str, Any]:
        """Parse Redis data into a dictionary
        
        Args:
            redis_data: Raw Redis data
            
        Returns:
            Parsed dictionary with decoded values
        """
        data_partner = {}
        for key, value in redis_data.items():
            key = key.decode('utf-8')
            value = value.decode('utf-8')
            
            if key == 'message':
                data = value.replace("'", '"')
                data_partner[key] = json.loads(data)
            else:
                data_partner[key] = value
                
        return data_partner

    def _get_redis_data(self, request_ref: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Get and parse data from Redis
        
        Args:
            request_ref: Reference ID for the request
            
        Returns:
            Tuple of (parsed_data, error_message)
        """
        try:
            redis_data = REDIS_USSD_DB.hgetall(request_ref)
            if not redis_data:
                return None, f'Request not found in Redis for {request_ref}'
                
            return self._parse_redis_data(redis_data), None
            
        except redis.RedisError as exc:
            return None, f'Redis Error: {exc}'

    def _check_status(self, request_ref: str, operator: str) -> Tuple[ServiceResponse, str]:
        """Check activation status for a given request reference and operator
        
        Args:
            request_ref: Reference ID for the request
            operator: Operator identifier
            
        Returns:
            Tuple of (ServiceResponse, log_message)
        """
        log_message = 'check activation status'
        result = ServiceResponse(ret_code=200, ret_msg='OK')

        # Validate authorization header
        self._create_log('1. Extract Authorization Header')
        wsgi_env = self.wsgi_environ
        auth_header = wsgi_env.get('HTTP_AUTHORIZATION')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return ServiceResponse(401, 'Unauthorized - Invalid Authorization Header'), \
                   f'{log_message} - failed (Invalid Authorization Header)'

        # Validate token
        self._create_log('2. Validate token')
        token_valid, token_message = self._validate_token()
        
        if not token_valid:
            return ServiceResponse(401, token_message), \
                   f'{log_message} - failed (Token Validation Error)'

        # Get LDAP token
        self._create_log('3. Fetch LDAP Token')
        try:
            ldap_response = self.invoke(SERVICE_LDAP, LDAP_AUTH)
            ldap_token = json.loads(str(ldap_response['response']['ret_result']).replace("'", '"'))
            
            if 'status' in ldap_token:
                return ServiceResponse(ldap_token['status'], ldap_token['message']), \
                       f'{log_message} - failed (LDAP Token Error)'
                       
        except Exception as exc:
            return ServiceResponse(500, f'Internal Server Error (Invalid LDAP Token Format): {exc}'), \
                   f'{log_message} - failed (LDAP Token Parsing Error)'

        # Get Redis data
        self._create_log(f'4. Fetch Redis Data for {request_ref}')
        redis_data, redis_error = self._get_redis_data(request_ref)
        
        if redis_error:
            return ServiceResponse(500, f'Internal Server Error: {redis_error}'), \
                   f'{log_message} - failed (Redis Error)'
                   
        if not redis_data:
            return ServiceResponse(404, f'Request not found in Redis for {request_ref}'), \
                   f'{log_message} - failed (Request Not Found)'

        # Validate operator
        if redis_data.get('operator') != operator:
            return ServiceResponse(404, f'Operator mismatch: {redis_data["operator"]} != {operator}'), \
                   f'{log_message} - failed (Operator Mismatch)'

        # Prepare success response
        result.ret_result = {
            "amount": redis_data.get('amount'),
            "service_type": redis_data.get('service_type'),
            "transaction_date": redis_data.get('transaction_date'),
            "offer_ref": redis_data.get('offer_ref'),
            "customer_id": redis_data.get('customer_id'),
            "offre_refnum": redis_data.get('offre_refnum'),
            "caller_num": redis_data.get('caller_num'),
            "bundle_name": redis_data.get('bundle_name'),
            "client_refnum": redis_data.get('client_refnum'),
            "partner_ref": redis_data.get('partner_ref'),
            "operator": redis_data.get('operator'),
            "device_id": redis_data.get('device_id'),
        }
        
        return result, f'{log_message} - successful (Transaction Found)'

    def handle_GET(self) -> None:
        """Handle GET requests to check activation status"""
        request_ref = self.request.input.request_ref
        operator = self.request.input.operator
        
        result, log_message = self._check_status(request_ref, operator)
        
        self._create_log(f"=> FINAL RESPONSE {BLUELINE_SERVICE_NAME.upper()} \n {result.__dict__}")
        
        self.response.payload = result.__dict__
        self.response.status_code = result.ret_code
        self.logger.info(log_message)
        self.log_output(BLUELINE_SERVICE_NAME)
