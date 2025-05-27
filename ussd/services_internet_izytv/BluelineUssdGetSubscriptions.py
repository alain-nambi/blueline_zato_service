# -*- coding: utf-8 -*-

"""
Copyright (C) Aug 2024 Blueline, Henintsoa Moriaa
Updated by: Alain Nambii on 2025-01-29

Licensed under LGPLv3.

USSD Subscription Service - Handles retrieval of mobile subscriptions through USSD gateway
"""
import json
import logging
import redis
import requests
from requests.auth import HTTPBasicAuth
from six.moves.configparser import ConfigParser
from zato.server.service import Service
import xmltodict

# Configuration setup
CONFIG = ConfigParser()
CONFIG.read("/etc/auth_partner/auth_partner.conf")

# Redis configuration
# REDIS_SERVER = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_SERVER")
# REDIS_PORT = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_PORT")
# REDIS_TOKEN_DB = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_DB")
REDIS_TOKEN_DB = redis.Redis(db=4)  # Using database 4 for token storage

# Service constants
SERVICE_NAME = "blueline.ussd.get.subscriptions"
AUTH_HEADER_PREFIX = "Bearer "
EXTERNAL_API_URL = "https://api.blueline.mg/staging/ussd/v1/clients/{}/subscriptions"
LDAP_SERVICE_NAME = "blueline.ldap.request.token"
SOAP_SERVICE_NAME = "BluelineBluebaseS4DService"

# Authentication credentials
LDAP_CREDENTIALS = {"username": "zato", "password": "qlnwFMKXqAe2soL7eYsx"}

MAX_AIRTEL_SUBSCRIPTIONS = 3


class BluelineUssdGetSubscriptions(Service):
    """
    Zato service handling USSD subscription requests with authentication and Redis token validation
    """

    name = SERVICE_NAME

    class SimpleIO:
        """
        Input and output definitions for the service
        """

        input_required = (
            "operator",
            "caller_num",
            "service_type",
            "device_name",
            "customer_id",
        )
        default_value = "UNKNOWN"
        
    def _create_log(self, message):
        border = "-" * (len(message) + 6)
        return logging.info(f"\n{border}\n  {message}  \n{border}")

    def _prepare_soap_payload(self, call_service, data):
        """
        Prepare the payload for the SOAP request
        """
        SOAP_PAYLOAD = {
            "root": {
                "header": {
                    "version": "1",
                    "param1": call_service,
                    "ident": CONFIG["BLUEBASE"]["ident"],
                    "psw": CONFIG["BLUEBASE"]["pswd"],
                },
                "data": {
                    "operator": data.get("operator"),
                    "caller_num": data.get("caller_num"),
                    "device_id": data.get("device_name"),
                    "client_refnum": data.get("customer_id"),
                    "service_type": data.get("service_type"),
                },
            }
        }
        return SOAP_PAYLOAD

    def _send_error_report(self, error_message):
        """
        Sends an email notification when a SOAP request fails
        """
        email_payload = {
            "mail_to": "nambinintsoa.rakotoarivelo@staff.blueline.mg",  # dev@si.blueline.mg
            "mail_from": "zato3dev@si.blueline.mg",
            "mail_text": f"Error during SOAP request or response processing: {error_message}",
            "title": f"{SERVICE_NAME} SOAP Request Error",
        }
        self.invoke("blueline.send.email", email_payload, as_bunch=True)

    def _send_soap_request(self, payload):
        """
        Send SOAP request to external service
        """
        try:
            # Convert payload dictionary to XML format
            data_xml = xmltodict.unparse(payload)
            logging.info(f"{SERVICE_NAME} SOAP Request: {data_xml}")

            # Establish a connection with the SOAP service
            with self.outgoing.soap.get(SOAP_SERVICE_NAME).conn.client() as client:
                return client.service.S4D(data_xml)

        except Exception as e:
            error_message = f"{SERVICE_NAME} SOAP Request failed: {str(e)}"
            logging.error(error_message)
            # Send email notification report
            self._send_error_report(error_message)
            return None

    def _validate_authorization(self, wsgi_env):
        """
        Validate Bearer token from authorization header
        """
        http_auth = wsgi_env.get("HTTP_AUTHORIZATION", "")
        if not http_auth.startswith(AUTH_HEADER_PREFIX):
            return False, None, "Missing or invalid authorization header"

        return True, http_auth.split(" ")[1].strip(), None

    def _check_redis_token(self, token):
        """
        Validate token against Redis storage
        """
        redis_key = f"token:{token}"
        return REDIS_TOKEN_DB.exists(redis_key)

    def _get_ldap_token(self):
        """
        Retrieve LDAP authentication token from internal service
        """
        try:
            response = self.invoke(LDAP_SERVICE_NAME, LDAP_CREDENTIALS)
            return json.loads(response["response"]["ret_result"].replace("'", '"'))
        except Exception as e:
            logging.error(f"{SERVICE_NAME} [LDAP token request failed] {str(e)}")
            return {"status": 500, "error": "LDAP service unavailable"}

    def _process_soap_response(self, response, input_data):
        """Process and normalize SOAP response data"""
        try:
            data = xmltodict.parse(response).get("root", {}).get("data", {})
            subscriptions = data.get("bouquet", [])
            operator = input_data.get("operator")
            caller_num = input_data.get("caller_num")

            if not isinstance(subscriptions, list):
                subscriptions = [subscriptions]

            formatted_subscriptions = [
                {"name": sub["intitule"], "value": sub["date_fin"]}
                for sub in subscriptions
            ]

            if (
                len(formatted_subscriptions) > MAX_AIRTEL_SUBSCRIPTIONS
                and operator.lower() == "airtel"
            ):
                formatted_subscriptions = formatted_subscriptions[
                    :MAX_AIRTEL_SUBSCRIPTIONS
                ]

            return {
                "data": formatted_subscriptions,
                "num_is_mine": data.get("num_is_mine"),
                "caller_num": caller_num,
            }
        except (KeyError, AttributeError) as e:
            logging.error(f"{SERVICE_NAME} SOAP response processing error: {str(e)}")
            return None

    def handle_GET(self):
        """
        Main request handler for GET method service
        """
        # Initialize response parameters
        result = {"ret_code": 200, "ret_msg": "OK", "ret_result": None}
        log_message = "USSD get subscriptions"

        try:
            self._create_log(f"{str(SERVICE_NAME).upper()}")
            
            # 1. Authorization validation
            self._create_log("1. Authorization validation OK")
            auth_valid, token, auth_error = self._validate_authorization(
                self.wsgi_environ
            )
            if not auth_valid:
                result.update(
                    {"ret_code": 401, "ret_msg": auth_error or "Unauthorized"}
                )
                raise PermissionError(auth_error)

            # 2. Redis token validation
            self._create_log("2. Redis token validation OK")
            if not self._check_redis_token(token):
                result.update({"ret_code": 403, "ret_msg": "Invalid token"})
                log_message += " _ invalid token"
                raise PermissionError("Token validation failed")

            # 3. LDAP token retrieval
            self._create_log("3. LDAP token retrieval OK")
            ldap_token = self._get_ldap_token()
            if "status" in ldap_token:
                result.update(
                    {
                        "ret_code": ldap_token["status"],
                        "ret_msg": ldap_token["error", "LDAP service error"],
                    }
                )
                log_message += " _ ldap error"
                raise ConnectionError("LDAP service error")

            # 4. Prepare SOAP payload
            self._create_log("4. Prepare SOAP payload OK")
            soap_payload = self._prepare_soap_payload(
                call_service="ussd_get_infos", data=self.request.input
            )

            # 5. Send SOAP request
            self._create_log("5. Send SOAP request OK")
            soap_response = self._send_soap_request(soap_payload)

            # 6. Process SOAP response
            self._create_log("6. Process SOAP response OK")
            processed_response = self._process_soap_response(
                response=soap_response, input_data=self.request.input
            )

            # 7. Finalize response
            self._create_log("7. Finalize response OK")
            result.update(
                {
                    "ret_result": {
                        "data": processed_response["data"],
                        "num_is_mine": processed_response["num_is_mine"],
                        "caller_num": self.request.input.caller_num,
                    }
                }
            )
        except Exception as e:
            logging.error(f"{SERVICE_NAME} {log_message} {str(e)}")
            log_message += " _ processing error"
            if result["ret_code"] == 200:
                result.update({"ret_code": 500, "ret_msg": "Internal processing error"})

        self.response.payload = result
        self.response.status_code = result["ret_code"]
        self.log_output(SERVICE_NAME)