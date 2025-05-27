# -*- coding: utf-8 -*-

"""
Copyright (C) Aug 2024 Blueline, Henintsoa Moriaa
Licensed under LGPLv3.
"""

# stdlib
import ast
import logging
import datetime
import random
import redis, re
import string

from six.moves.configparser import ConfigParser
import pytds
from json import dumps, loads
from zato.common import DATA_FORMAT

from zato.server.service import Service

CONFIG = ConfigParser()
CONFIG.read("/etc/auth_partner/auth_partner.conf")

AUTH_PARTNER_REDIS_SERVER = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_SERVER")
AUTH_PARTNER_REDIS_PORT = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_PORT")
AUTH_PARTNER_REDIS_DB = CONFIG.get("REDIS", "AUTH_PARTNER_REDIS_DB")

# Global Definitions
blueline_service_name = 'blueline.auth.request.token.partner'

class BluelineRequestTokenPartner(Service):
    
    name = blueline_service_name

    class SimpleIO:
        input_required = ('login', 'password')
        # output_required = ('ret_code', 'ret_msg', 'ret_result')
        default_value = 'UNKNOWN'

    # Log and Return Response
    def handle_POST(self):
        """ External Authenticatoin """
        login = self.request.input.login
        password = self.request.input.password
        
        ret_result = {}
        log_message = 'get token'

        list_ext_partner = self.kvdb.conn.get('external.partner.login')
        dict_login = ast.literal_eval(list_ext_partner)
        if login in dict_login.keys() and dict_login[login] == password:
            ret_code = 200
            ret_msg = 'success'
            token = self._generate_random_word()
            values = {
                'login' : login, 
                'token' : token
            }
            insert_into_redis = self._insert_into_redis(values)
            if insert_into_redis != 200:
                ret_code = insert_into_redis['code']
                ret_msg = 'Internal Error Server'
                logging.error('[BluelineRequestTokenPartner][REDIS] ERROR INSERTION INTO REDIS : {}'.format(insert_into_redis['error']))
            else:
                ret_result['token'] = token
                ret_result['token_type'] = 'Bearer'
                ret_result['expires_in'] = 3600
                dict_result = {"token" : token}
                logging.error('[BluelineRequestTokenPartner][REDIS] SUCCESS : {}'.format(values))
        else:
            ret_code = 401
            ret_msg = 'Login/Password incorrect'
            log_message+=' Error: '

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

    def _generate_random_word(self):
        """  generate token 50-character word """
        length=50
        # Define the character set
        characters = string.ascii_letters + string.digits
        # Generate a random word
        random_word = ''.join(random.choice(characters) for _ in range(length))
        return random_word
    
    def _insert_into_redis(self, values):
        """ insert token data in redis """
        try:
            r = redis.Redis(
                host=AUTH_PARTNER_REDIS_SERVER,
                port=AUTH_PARTNER_REDIS_PORT,
                db=AUTH_PARTNER_REDIS_DB,
                charset="utf-8",
                decode_responses=True,
            )
            key = "token:{}".format(values['token'])
            r.hmset(
                key,
                {
                    "key": key,
                    "login": values['login'],
                    "token": values['token'],
                },
            )
            r.expire(key, 3600)
            return 200
        except Exception as e:
            status_code = 500
            return {"code" : status_code, "error" : "{}".format(e)}