# -*- coding: utf-8 -*-

"""
Copyright (C) Aug 2024 Blueline, Henintsoa Moriaa
Licensed under LGPLv3.
"""

# stdlib
import base64
import json
import logging
import redis, re, requests

import xmltodict

from requests.auth import HTTPBasicAuth

from six.moves.configparser import ConfigParser
from json import dumps, loads
from zato.common import DATA_FORMAT

from zato.server.service import Service

CONFIG = ConfigParser()
CONFIG.read("/etc/auth_partner/auth_partner.conf")

# REDIS_SERVER = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_SERVER")
# REDIS_PORT = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_PORT")
# REDIS_TOKEN_DB = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_DB")

REDIS_TOKEN_DB = redis.Redis(db=4)

# Global Definitions
blueline_service_name = 'blueline.ussd.get.client.invoice'

class BluelineUssdGetClientInvoice(Service):
    
    name = blueline_service_name

    class SimpleIO:
        input_required = (
            'operator', 'caller_num', 'invoice_type', 'customer_refnum', 
        )
        # output_required = ('ret_code', 'ret_msg', 'ret_result')
        default_value = 'UNKNOWN'

    # Log and Return Response
    def handle_GET(self):
        """ Get all invoices relative to a client """
        # token = self.request.input.token
        operator = self.request.input.operator
        caller_num = self.request.input.caller_num
        invoice_type = self.request.input.invoice_type
        customer_refnum = self.request.input.customer_refnum
        
        ret_result = None
        log_message = 'get invoice '

        ret_code = 200
        ret_msg = 'OK'

        # get header, check auth type, check token
        wsgi = self.wsgi_environ
        logging.error('[BluelineUssdGetClientInvoice][wsgi][request] : {}'.format(wsgi))
        http_auth = wsgi['HTTP_AUTHORIZATION']
        if not http_auth or not http_auth.startswith('Bearer '):
            # self.response.status_code = 401
            # self.response.body = 'Unauthorized'
            # return
            ret_code = 401
            ret_msg = 'Unauthorized'
            log_message += ' _ failed'

        token = http_auth.split(' ')[1]
        redis_key = 'token:{}'.format(str(token).strip())
        token_value = REDIS_TOKEN_DB.hgetall(redis_key)
        logging.error('[BluelineUssdGetClientInvoice][Redis][check_token] : {}'.format(token_value))
        if not token_value:
            ret_code = 401
            ret_msg = 'Unauthorized'
            log_message += ' _ wrong token'
        else:
            # code line
            dict_values = {
                'operator' : operator,
                'caller_num' : caller_num,
                'type' : invoice_type,
                'client_refnum' : customer_refnum
            }
            try:
                bluebase_response = self.send_data_bluebase(dict_values)
            except Exception as exception:
                logging.error('[BluelineUssdGetClientInvoice][send data to bluebase] error : {}'.format(exception))
                ret_code = 500
                ret_msg = 'Internal Server Error'
            else:
                parsed_response = xmltodict.parse(bluebase_response)
                if str(parsed_response['root']['header']['errorNum']) == '0':
                    ret_result = parsed_response['root']['data']
                else:
                    ret_code = parsed_response['root']['header']['errorNum']
                    ret_msg = parsed_response['root']['header']['errorTx']

        self.response.payload = {
            'ret_msg' : ret_msg,
            'ret_code' : ret_code,
            'ret_result' : ret_result
        }
        # self.response.payload.ret_msg = ret_msg
        # self.response.payload.ret_code = ret_code
        # self.response.payload.ret_result = ret_result
        self.response.status_code = ret_code
        self.logger.info(log_message)
        self.log_output(blueline_service_name)
    

    def send_data_bluebase(self, dicts):
        """Send data to bluebase"""
        bluebase_payload = {
            "root": {
                "header": {
                    "version": "1",
                    "param1": "ussd_fact_getlist",
                    "ident": CONFIG['BLUEBASE']['ident'],
                    "psw": CONFIG['BLUEBASE']['pswd'],
                },
                "data": {
                    "operator": dicts["operator"],
                    "caller_num": dicts["caller_num"],
                    "type": dicts["type"],
                    "client_refnum": dicts["client_refnum"],
                },
            }
        }
        try:
            with self.outgoing.soap.get("BluelineBluebaseS4DService").conn.client() as client:
                self.logger.info(
                    f"payload sent to s4d 'ussd_fact_getlist' : {bluebase_payload}"
                )
                data_xml = xmltodict.unparse(bluebase_payload)
                self.logger.info(
                    f"payload xml sent to s4d 'ussd_fact_getlist' : {data_xml}"
                )
                response = client.service.S4D(data_xml)
                return response
        except Exception as e:
            self.invoke(
                "blueline.send.email",
                {
                    'mail_to': "dev@si.blueline.mg",
                    'mail_from': "zato3dev@si.blueline.mg",
                    'mail_text': (
                        "service: {}\n\n"
                        "affected operation: {}\n\n"
                        "error: {}"
                        .format(
                            blueline_service_name,
                            "Sending data to bluebase",
                            str(e),
                        )
                    ),
                    'title': "[BluelineUssdGetClientInvoice] USSD Facture | Erreur ",
                },
                as_bunch=True,
            )
            logging.info(
                "[BluelineUssdGetClientInvoice] Error report sent by email to "
                "dev@si.blueline.mg\n"
            )
            raise ValueError(e)
