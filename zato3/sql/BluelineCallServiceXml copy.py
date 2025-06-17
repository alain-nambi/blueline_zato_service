# -*- coding: utf-8 -*-
# zato: ide-deploy=False

"""
This service act like a Gateway for Soap Client to call our RestApi Service

Copyright (C) 2021 Blueline
Licensed under LGPLv3.

Update on 10 April 2025 (latest version)
* Make code same to prod version
"""

# pylint: disable=invalid-name
# pylint: disable=logging-fstring-interpolation

# Standard library imports ...
import json
import logging
import re
import unicodedata
from ast import literal_eval
from collections import defaultdict
from configparser import ConfigParser
from xml.dom.minidom import parseString, Document
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import tostring

# Third party library imports ...
import dicttoxml
import xmltodict
from bool_to_python import bool_to_python
from lxml import etree
from smpp import *  # pylint: disable=wildcard-import

# Zato
from zato.server.service import Service


dicttoxml.LOG.setLevel(logging.ERROR)

# Global Definitions
blueline_service_name = "blueline.call.service.xml"


#
# Global Definitions and configuration
#


def read_config() -> ConfigParser:
    """Read the config file for blueline_call_service_xml.

    Returns:
        ConfigParser: ConfigParser instance after reading the config file.
    """
    config = ConfigParser()
    config.read("/etc/zato/blueline_call_service_xml/blueline_call_service_xml.ini")
    return config


ALLGOOD_RETCODE = "405000000"

CONFIG = read_config()
LIST_WEB_SERVICES = json.loads(CONFIG["DEFAULT"]["list_web_services"])
LIST_ALLOWED_USERS = json.loads(CONFIG["DEFAULT"]["list_allowed_users"])
#
# end setting up conf file
#


# by L.
# function change dict to xml
def dict_to_xml(tag, dictionnary):
    """
    Transform a dictionnary to XML
    """

    elem = Element(tag)

    for key, val in dictionnary.items():
        if isinstance(val, dict):
            child = dict_to_xml(str(key), val)
        else:
            child = Element(key)
            child.text = str(val)

        elem.append(child)

    return elem


class BluelineCallServiceXml(Service):
    """This service act like a Gateway for Soap Client to call our RestApi Service"""

    name = blueline_service_name

    def has_generic_response(self, service_name):
        """Check if service has generic response.

        Generic response has the following structure:
            - ret_code
            - ret_msg
            - result
        """
        list_of_service_having_generic_response = [
            # service having generic response here ...
            "blueline.mvola.init_transaction.service",
            "blueline.mvola.redis.transaction_status.service",
            "blueline.generic.call.external.rest.service",
        ]

        return service_name in list_of_service_having_generic_response

    def create_xml_return(
        self,
        ident,
        errorNum,
        errorTx,
        value_result,
        name_tag,
        name_tag_1,
        simple_property,
        sql_property,
        solde,
    ):
        """Create the returned xml string"""
        res = (
            "<root>\n\t<header>\n\t\t<ident>%s</ident>\n\t\t<errorNum>%s</errorNum>\n\t\t<errorTx>%s</errorTx>\n\t</header>\n\t<data>"
            % (ident, errorNum, errorTx)
        )

        if solde:
            res += "\n\t\t<solde> %s </solde>" % (solde)
        if type(value_result) is list:
            for values in value_result:
                fields = values.split(",")
                res += "\n\t\t<" + name_tag + ">"
                for field in fields:
                    value = field.split(":")
                    if len(value) > 1:
                        res += (
                            "\n\t\t\t<"
                            + value[0]
                            + ">"
                            + value[1]
                            + "</"
                            + value[0]
                            + ">"
                        )

                if simple_property != []:
                    # res += '\n\t\t\t<' + name_tag_1 + '>'
                    for field in simple_property:
                        res += "\n\t\t\t<" + name_tag_1 + ">"
                        entries = field.split(":")[1:]
                        for simpleprop in entries:
                            value = simpleprop.split(",")
                            if len(value) > 1:
                                res += (
                                    "\n\t\t\t\t<"
                                    + value[0]
                                    + ">"
                                    + value[1]
                                    + "</"
                                    + value[0]
                                    + ">"
                                )
                            elif len(value) == 1:
                                res += "\n\t\t\t\t<" + value[0] + "/>"
                        res += "\n\t\t\t</" + name_tag_1 + ">"
                    # res += '\n\t\t\t</' + name_tag_1 + '>'
                if sql_property != []:
                    for field in sql_property:
                        res += "\n\t\t\t<" + name_tag_1 + ">"
                        entries = field.split(",")
                        nbr_column = entries[len(entries) - 1]
                        del entries[len(entries) - 1]
                        for sqlprop in entries:
                            value = sqlprop.split(":")
                            res += "\n\t\t\t\t<col>"
                            if len(value) > 1:
                                res += "\n\t\t\t\t\t<key>" + value[0] + "</key>"
                                res += "\n\t\t\t\t\t<value>" + value[1] + "</value>"
                                # res += '\n\t\t\t\t<'+ value[0] + '>'+ value[1] + '</'+ value[0] + '>'
                            elif len(value) == 1:
                                res += "\n\t\t\t\t<key/>"
                                res += "\n\t\t\t\t<value/>"
                            res += "\n\t\t\t\t</col>"
                        res += "\n\t\t\t</" + name_tag_1 + ">"
                    res += "\n\t\t\t<nbr_col>" + nbr_column + "</nbr_col>"
                res += "\n\t\t</" + name_tag + ">"
        else:
            field = name_tag or "field"
            res += "\n\t\t<" + field + ">" + str(value_result) + "</" + field + ">"
        res += "\n\t</data>\n</root>"
        return res

    def create_xml_return_simple(
        self, ident, errorNum, errorTx, value_result, name_tag
    ):
        """Create the returned xml string for Cryptoguard"""
        res = (
            "<root>\n\t<header>\n\t\t<ident>%s</ident>\n\t\t<errorNum>%s</errorNum>\n\t\t<errorTx>%s</errorTx>\n\t</header>\n\t<data>"
            % (ident, errorNum, errorTx)
        )

        field = name_tag or "field"
        field = "" if field == "status" else field

        if field:
            res += "\n\t\t<" + field + ">" + str(value_result) + "</" + field + ">"
        else:
            res += "\n\t\t" + str(value_result)

        res += "\n\t</data>\n</root>"

        return res

    # Create return xml for blueline.managing.status.bln only
    def create_xml_return_status_bln(self, ident, errorNum, errorTx, value_result):
        """Create the returned xml string"""
        res = (
            "<root>\n\t<header>\n\t\t<ident>%s</ident>\n\t\t<errorNum>%s</errorNum>\n\t\t<errorTx>%s</errorTx>\n\t</header>\n\t<data>"
            % (ident, errorNum, errorTx)
        )

        res += "\n\t\t" + str(value_result)
        res += "\n\t</data>\n</root>"
        return res

    # # return xml for blueline.Managing.Customer.Bln only
    # def create_xml_return_customer_bln(self, ident, errorNum, errorTx, value_result):
    #     """Create the returned xml string"""
    #     res = (
    #         "<root>\n\t<header>\n\t\t<ident>%s</ident>\n\t\t<errorNum>%s</errorNum>\n\t\t<errorTx>%s</errorTx>\n\t</header>\n\t<data>"
    #         % (ident, errorNum, errorTx)
    #     )

    #     res += "\n\t\t" + str(value_result)
    #     res += "\n\t</data>\n</root>"
    #     return res

    # # by M.
    # # return xml for blueline.managing.status.bln only
    # def create_xml_return_bln(self, ident, errorNum, errorTx, value_result):
    #     """Create the returned xml string"""
    #     res = (
    #         "<root>\n\t<header>\n\t\t<ident>%s</ident>\n\t\t<errorNum>%s</errorNum>\n\t\t<errorTx>%s</errorTx>\n\t</header>\n\t<data>"
    #         % (ident, errorNum, errorTx)
    #     )

    #     res += "\n\t\t" + str(value_result)
    #     res += "\n\t</data>\n</root>"
    #     return res


    # by Mamisoa, a function to create wml return for blueline.django.merchant.create.ticket.sim
    def create_merchant_ticket_sim_return(self, ident, errorNum, errorTx, status, declaration_ref):
        """Create a simplified XML string with only status and declaration_ref"""
        res = (
            "<root>\n\t<header>\n\t\t<ident>%s</ident>\n\t\t<errorNum>%s</errorNum>\n\t\t<errorTx>%s</errorTx>\n\t</header>\n\t<data>"
            % (ident, errorNum, errorTx)
        )

        res += "\n\t\t<status>%s</status>" % (status)
        res += "\n\t\t<declaration_ref>%s</declaration_ref>" % (declaration_ref)
        res += "\n\t</data>\n</root>"
        return res



    def parse_input(self, root):
        """Parse input xml string from bluebase"""
        res = {"header": {}, "data": {}}
        if root is not None:
            for entry in ["header", "data"]:
                element = root.find(entry)
                for child in element.iter():
                    if child.tag != element.tag:
                        res[entry][child.tag] = child.text
        return res

    def parse_input_liste(self, root, liste):
        """Parse input xml string from bluebase"""
        res = defaultdict(list)
        data = root.find("data")
        if root is not None:
            for customer in data.findall(liste):
                part_id = customer.find("partner_id").text
                amount = customer.find("amount").text
                num_fac = customer.find("numero_facture").text
                res[liste].append(
                    {"partner_id": part_id, "amount": amount, "num_recu": num_fac}
                )
        return res

    def parse_input_caisse_liste(self, root, liste):
        """Parse input xml string from bluebase"""
        res = defaultdict(list)
        data = root.find("data")
        if root is not None:
            for receipt in data.findall(liste):
                amount = receipt.find("amount").text
                num_recu = receipt.find("num_recu").text
                refnum_unique = receipt.find("refnum_unique").text
                reference = receipt.find("num_recharge").text
                client_id = receipt.find("client_id").text
                refnum_client = receipt.find("refnum_client").text
                res[liste].append(
                    {
                        "amount": amount,
                        "num_recu": num_recu,
                        "reference": reference,
                        "client_id": client_id,
                        "refnum_unique": refnum_unique,
                        "refnum_client": refnum_client,
                    }
                )
        return res

    def parse_input_fac_list(self, root, liste):
        """Parse input xml string from bluebase"""
        res = defaultdict(list)
        data = root.find("data")
        param_dict = {}
        x = 0
        if root is not None:
            for customer in data.findall(liste):
                res[liste].append(
                    {
                        "partner_id": customer.find("partner_id"),
                        "amount": customer.find("amount"),
                        "refnum_facture": customer.find("refnum_facture"),
                        "numero_facture": customer.find("numero_facture"),
                        "date": customer.find("date"),
                        "date_maturity": customer.find("date_maturity"),
                        "name": customer.find("name"),
                        "file_nameSource": customer.find("pdv"),
                        "bank_name": customer.find("bank_name"),
                        "amount_currency": customer.find("amount_currency"),
                        "currency": customer.find("currency"),
                        "company": customer.find("company"),
                        "index": customer.find("index_in"),
                        "tva": customer.find("tva"),
                        "amount_currency_ht": customer.find("amount_currency_ht"),
                        "amount_currency_tva": customer.find("amount_currency_tva"),
                        "amount_tva": customer.find("amount_tva"),
                        "amount_ht": customer.find("amount_ht"),
                        "num_recharge": customer.find("num_recharge"),
                        "prelev_auto": customer.find("prelev_auto"),
                        "product_def": customer.find("product_def"),
                        "refnum_client": customer.find("refnum_client"),
                        "taux_currency": customer.find("taux_currency"),
                    }
                )
        return res

    def to_dict(self, element):
        """Change XML element to dict."""

        ret = {}
        if element.getchildren() == []:
            return element.text

        for elem in element.getchildren():
            subdict = self.to_dict(elem)
            ret[re.sub("{.*}", "", elem.tag)] = subdict

        return ret

    def blueline_tv_cryptoguard(
        self, param_header: dict, param_data: dict, name_tag: str
    ) -> None:
        """Handle blueline_tv cryptoguard call.

        Args:
            param_header (dict): parameter header send from SOAP Client.
            param_data (dict): parameter data send from SOAP Client.
            name_tag (str): name tag used to indentify something.
        """

        if param_header["param1"] == "blueline.tv.cryptoguard":
            self.call_cryptoguard_tv(param_header, param_data, name_tag)
        elif param_header["param1"] == "blueline.tv.cryptoguard.card.informations":
            self.call_cryptoguard_tv(
                param_header, param_data, name_tag, "card_informations"
            )
        elif param_header["param1"] == "blueline.tv.cryptoguard.get.infos.tv":
            self.call_cryptoguard_tv(param_header, param_data, name_tag, "get_infos_tv")
        elif param_header["param1"] == "blueline.tv.cryptoguard.activate.card":
            self.call_cryptoguard_tv(
                param_header, param_data, name_tag, "activate_card"
            )
        elif param_header["param1"] == "blueline.tv.cryptoguard.deactivate.card":
            self.call_cryptoguard_tv(
                param_header, param_data, name_tag, "deactivate_card"
            )
        elif param_header["param1"] == "blueline.tv.cryptoguard.set.card.group":
            self.call_cryptoguard_tv(
                param_header, param_data, name_tag, "set_card_group"
            )
        elif param_header["param1"] == "blueline.tv.cryptoguard.subscribe":
            self.call_cryptoguard_tv(param_header, param_data, name_tag, "subscribe")
        elif param_header["param1"] == "blueline.tv.cryptoguard.revoke":
            self.call_cryptoguard_tv(param_header, param_data, name_tag, "revoke")
        elif param_header["param1"] == "blueline.tv.cryptoguard.check.pairing":
            self.call_cryptoguard_tv(
                param_header, param_data, name_tag, "check_pairing"
            )
        elif param_header["param1"] == "blueline.tv.cryptoguard.pairing":
            self.call_cryptoguard_tv(param_header, param_data, name_tag, "pairing")
        elif param_header["param1"] == "blueline.tv.cryptoguard.depairing":
            self.call_cryptoguard_tv(param_header, param_data, name_tag, "depairing")
        elif param_header["param1"] == "blueline.tv.cryptoguard.dump.card.tv":
            self.call_cryptoguard_tv(param_header, param_data, name_tag, "dump_card_tv")
        elif param_header["param1"] == "blueline.tv.cryptoguard.test":
            self.call_cryptoguard_tv(param_header, param_data, name_tag)

    def call_cryptoguard_tv(
        self, param_header: dict, param_data: dict, name_tag: str, method=""
    ) -> None:
        """Call TV Cryptoguard service.

        Args:
            param_header (dict): parameter header send from SOAP Client.
            param_data (dict): parameter data send from SOAP Client.
            name_tag (str): name tag used to indentify something.
            method (str, optional): method to call inside the cryptoguard service. Defaults to "".
        """

        if param_header["param1"] != "blueline.tv.cryptoguard.test":
            param_header["param1"] = "blueline.tv.cryptoguard"
        if method:
            param_data["method"] = method
        response = self.invoke(param_header["param1"], param_data, as_bunch=True)
        if param_data["method"] == "get_stb":
            name_tag = "stb"

        errorNum = response.response_elem.ret_code
        status = response.response_elem.ret_msg
        value_result = response.response_elem.result

        # Parse to xml with expected values
        value_result = self.transform_json_to_xml(value_result, param_data["method"])

        errorTx = status

        xml_out = self.create_xml_return_simple(
            param_header["ident"], errorNum, errorTx, value_result, name_tag
        )
        self.response.payload = xml_out

    def transform_json_to_xml(self, value_result, method="") -> str:
        """Transform JSON to XML and the way to do it depending on the used method.

        Args:
            value_result (Any): Result to be parsed into XML.
            method (str, optional): method used for the call. Defaults to "".

        Raises:
            ValueError: When the value_result can not be parsed into XML.

        Returns:
            str: XML string that correspond to the given json value_result.
        """
        try:
            # TODO : surely, THere is a better way to handle this 'if' statement below,
            if str(value_result).startswith('00') or str(value_result).strip() in ["Pas de stb", "OK"]:
                dict = {'result': value_result}
                value_result = str(dict)
            value_result = literal_eval((value_result))
            value_result = dicttoxml.dicttoxml(
                value_result, root=False, attr_type=False
            ).decode()

            logging.info(
                f"[BluelineCallServicXml][TransformJsonToXml] value result : {value_result}"
            )

            if method == "card_informations":
                value_result = str(value_result).replace("item", "pack")
            elif method == "get_infos_tv":
                value_result = (
                    str(value_result)
                    .replace("<service><item>", "<service>")
                    .replace("</item></service>", "</service>")
                    .replace("</item><item>", "</service><service>")
                )
            elif method == "dump_card_tv":
                value_result = str(value_result).replace("item", "card")
            elif method == "get_stb":
                value_result = (
                    str(value_result)
                    .replace("<result>", "")
                    .replace("</result>", "")
                )
        except ValueError as err:
            raise ValueError("Can't parse to XML") from err

        return value_result

    # Log and Return Response
    def handle(self):  # pylint: disable=missing-function-docstring
        self.log_input(blueline_service_name)

        namespace = "dsi.blueline.mg/ns/blztdv"
        errorNum = ""
        errorTx = ""
        bool_xml = False
        SimpleProperty = []
        sql_property = []
        solde = 0
        xml_out = ""
        value_result = ""
        bool_status = False
        name_tag = "status"
        name_tag_1 = "property"
        liste_web_service = [
            "blueline.bluedesk.ticket",
            "blueline.sms.openvox",
            "blueline.zato.odoo.account.fas.lot",
            "blueline.zato.odoo.account.lot",
            "blueline.call.service.sql",
            "blueline.zato.odoo.customer.create",
            "blueline.zato.odoo.customer.update",
            "blueline.zato.sage.customer.create",
            "blueline.zato.odoo.receipt.byday",
            "blueline.zato.odoo.customer.get.partnerid",
            "blueline.zato.odoo.customer.get.balance",
            "blueline.zato.sage.get.solde",
            "blueline.zato.odoo.account.prepaid",
            "blueline.zato.odoo.account.byfile.async",
            "blueline.zato.odoo.account.byfile.async.new",
            "blueline.django.merchant.supply.list",
            "blueline.django.merchant.supply.status",
            "blueline.django.merchant.supply.v.3",
            "blueline.django.merchant.supply",
            "blueline.django.merchant.supply.dev",
            "blueline.managing.status.bln",
            "blueline.mvola.init_transaction.service",
            "blueline.mvola.redis.transaction_status.service",
            "blueline.airtel.init.transaction",
            "blueline.sage.account.prepaid.daily",
            "blueline.sage.account.sera.daily",
            "blueline.django.merchant.create.ticket.sim", #service create ticket sim
        ] + LIST_WEB_SERVICES  # By L. : Try to add your service inside the config file.
        liste_cryptoguard_service = [
            "blueline.tv.cryptoguard",
            "blueline.tv.cryptoguard.card.informations",
            "blueline.tv.cryptoguard.get.infos.tv",
            "blueline.tv.cryptoguard.activate.card",
            "blueline.tv.cryptoguard.deactivate.card",
            "blueline.tv.cryptoguard.set.card.group",
            "blueline.tv.cryptoguard.subscribe",
            "blueline.tv.cryptoguard.revoke",
            "blueline.tv.cryptoguard.check.pairing",
            "blueline.tv.cryptoguard.pairing",
            "blueline.tv.cryptoguard.depairing",
            "blueline.tv.cryptoguard.dump.card.tv",
            "blueline.tv.cryptoguard.test",
        ]
        liste_allowed_user = [
            "Zato-4D",
            "Zato",
            "4D",
            "Moria",
        ] + LIST_ALLOWED_USERS  # By L. : Try to add users inside the config file.
        is_xml_out_ok = False

        request = self.request.payload

        liste_pwd = [
            self.kvdb.conn.get("service.new.password"),
            self.kvdb.conn.get("service.password"),
        ]

        todict = self.to_dict(request)
        logging.info(
            f"[BluelineCallServiceXml][DataSent] Data sent XMLtoDict : {todict}"
        )
        inp = self.parse_input(request)
        param_data = inp["data"]
        param_header = inp["header"]
        param_data["ident"] = param_header["ident"]
        logging.warning(
            f"{blueline_service_name}/{param_header['param1']} Input Data {param_data}"
        )
        if param_data["ident"] not in liste_allowed_user:
            raise ValueError("User is not allowed to use this service")

        logging.info(
            f"[BluelineCallServiceXml][Login] {param_data['ident']} used : {param_header['param1']}"
        )

        if param_header["psw"] not in liste_pwd:
            errorNum = "9003"
            errorTx = "redis password Error"
        elif param_header["param1"] not in (
            liste_web_service + liste_cryptoguard_service
        ):
            errorNum = "9002"
            errorTx = "Service not define"

        elif param_header["param1"] in liste_cryptoguard_service:
            is_xml_out_ok = True
            self.blueline_tv_cryptoguard(param_header, param_data, name_tag)

        elif param_header["param1"] == "blueline.sms.openvox":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
            if errorNum == "0":
                value_result = response.response_elem.result
            elif errorNum != "200":
                # value_result = response.response_elem.result
                value_result = "Erreur"

        elif param_header["param1"] == "blueline.zato.odoo.account.fas.lot":
            liste = "facture"
            inpx = self.parse_input_fac_list(request, liste)
            param_data[liste] = inpx[liste]
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
        elif param_header["param1"] == "blueline.zato.odoo.account.lot":
            liste = "facture"
            inpx = self.parse_input_fac_list(request, liste)
            param_data[liste] = inpx[liste]
            name_tag = "odoo"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status

        elif param_header["param1"] == "blueline.bluedesk.ticket":
            is_xml_out_ok = True
            if param_data["method"] == "get_ticket":
                name_tag = "ticket"

            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = response.response_elem.result

            value_result = self.transform_json_to_xml(value_result)

            errorTx = status

            xml_out = self.create_xml_return_simple(
                param_header["ident"], errorNum, errorTx, value_result, name_tag
            )
            self.response.payload = xml_out

        # by M.
        # blueline.Managing.status.bln
        elif param_header["param1"] == "blueline.managing.status.bln":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response["response_elem"]["ret_code"]
            errorTx = response["response_elem"]["ret_msg"]
            value_result = response["response_elem"]["result"]

            # decode result
            value_result = unicodedata.normalize("NFKD", value_result)
            value_result = value_result.encode("ascii", "ignore")
            value_result = value_result.decode()

            dict_str = literal_eval(value_result)

            final = dict_to_xml("root", dict_str)
            final = tostring(final).decode("utf-8")
            value_result = final

            value_result = value_result.replace("<root>", "")
            value_result = value_result.replace("</root>", "")

            is_xml_out_ok = True

            xml_out = self.create_xml_return_status_bln(
                param_header["ident"], errorNum, errorTx, value_result
            )
            logging.info("[blueline.managing.status.bln] XML :" + value_result)
            self.response.payload = xml_out

        # # by M.
        # # blueline.Managing.Customer.Bln
        # elif param_header["param1"] == "blueline.Managing.Customer.Bln":
        #     response = self.invoke(param_header["param1"], param_data, as_bunch=True)
        #     errorNum = response["response_elem"]["ret_code"]
        #     errorTx = response["response_elem"]["ret_msg"]
        #     value_result = response["response_elem"]["result"]

        #     # decode result
        #     value_result = unicodedata.normalize("NFKD", value_result)
        #     value_result = value_result.encode("ascii", "ignore")
        #     value_result = value_result.decode()

        #     dict_str = literal_eval(value_result)

        #     final = dict_to_xml("root", dict_str)
        #     final = tostring(final).decode("utf-8")
        #     value_result = final

        #     value_result = value_result.replace("<root>", "")
        #     value_result = value_result.replace("</root>", "")

        #     is_xml_out_ok = True

        #     xml_out = self.create_xml_return_customer_bln(
        #         param_header["ident"], errorNum, errorTx, value_result
        #     )
        #     logging.info("XML :" + value_result)
        #     self.response.payload = xml_out

        elif param_header["param1"] == "blueline.call.service.sql":
            name_tag = "sql"
            name_tag_1 = "sql_infos"
            # response = self.invoke(param_header['param1'], param_data, data_format=DATA_FORMAT.JSON)
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.error_code
            status = response.response_elem.error_msg
            sql_property = response.response_elem.result
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""
                SimpleProperty = []
                sql_property = []
            if errorNum == " ":
                errorNum = "400"
                errorTx = "0 line"
                value_result = ""
                SimpleProperty = []
                sql_property = []

        elif param_header["param1"] == "blueline.zato.odoo.customer.create":
            # name_tag = "partner_id"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.zato.odoo.customer.update":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.zato.sage.customer.create":
            name_tag = "partner_id"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.zato.odoo.receipt.byday":
            # name_tag = "id_transaction_dest"
            name_tag = "msg"
            liste = "receipt"
            inpx = self.parse_input_caisse_liste(request, liste)
            param_data[liste] = inpx[liste]
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.zato.odoo.customer.get.partnerid":
            name_tag = "odoo"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.zato.odoo.customer.get.balance":
            name_tag = "solde"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.zato.sage.get.solde":
            name_tag = "solde"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.error_code
            status = response.response_elem.error_msg
            value_result = response.response_elem.solde
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status

        elif param_header["param1"] == "blueline.zato.odoo.account.prepaid":
            name_tag = "id_transaction_dest"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.ret_code
            status = response.response_elem.ret_msg
            value_result = response.response_elem.get("id_transaction_dest", "DEFAULT")
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.zato.odoo.account.byfile.async":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.error_code
            status = response.response_elem.error_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        # call blueline.zato.odoo.account.byfile.async.news
        elif param_header["param1"] == "blueline.zato.odoo.account.byfile.async.new":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.response_elem.error_code
            status = response.response_elem.error_msg
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""
        
        elif param_header["param1"] == "blueline.sage.account.prepaid.daily":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.sageprepaid_response.code
            status = response.sageprepaid_response.status
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        elif param_header["param1"] == "blueline.sage.account.sera.daily":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = response.sagesera_response.code
            status = response.sagesera_response.message
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""
                
        # airtel
        elif param_header["param1"] == "blueline.airtel.init.transaction":
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            response = json.loads(response)
            errorNum = response["response_elem"]["ret_code"]
            status = response["response_elem"]["ret_msg"]
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

        # supply sera
        elif "django.merchant.supply" in param_header["param1"]:
            name_tag = "supply"
            response = self.invoke(param_header["param1"], param_data, as_bunch=True)
            errorNum = literal_eval(response.supplyrequest_response.code)
            value_result_supply = response.supplyrequest_response.message

            if errorNum == 200:
                errorTx = ""
                value_result = literal_eval(value_result_supply)
            else:
                errorTx = value_result_supply
                value_result = ""

        
        elif "blueline.django.merchant.create.ticket.sim" in param_header["param1"]:
            response = self.invoke(param_header["param1"], param_data, as_bunch=False)
            #response = json.loads(response)
            logging.info(f"Response : {response}")
            # errorNum = response["response"]["ret_code"]
            # status = response["response"]["ret_msg"]
            # declaration_ref = response["response"].get("declaration_ref", "None")
            
            # Fix empty return
            errorNum = response["ret_code"]
            status = response["ret_msg"]
            declaration_ref = response.get("declaration_ref", "None")
            
            
            value_result = status
            if errorNum != ALLGOOD_RETCODE:
                errorTx = status
                value_result = ""

            is_xml_out_ok = True
            xml_out = self.create_merchant_ticket_sim_return(param_header["ident"], errorNum, errorTx, 
                                                             status, declaration_ref)
            logging.info(f"Response : {xml_out}")
            
            self.response.payload = xml_out


        elif self.has_generic_response(param_header["param1"]):
            #
            # Rewrite the parse_input process to invoke process
            #
            raw_xml_astring = etree.tostring(self.request.payload)
            raw_payload = xmltodict.parse(raw_xml_astring)
            payload = bool_to_python(raw_payload)
            param_header = payload["root"]["header"]
            param_data = payload["root"]["data"]
            raw_response = self.invoke(param_header["param1"], param_data)
            #
            # Bunch raw_response is not json_serializable
            #
            try:
                response = json.loads(raw_response)
            except TypeError:
                response = raw_response

            try:
                response_with_header = {
                    "root": {
                        "header": {
                            "ident": param_header["ident"],
                            "errorNum": response["response_elem"]["ret_code"],
                            "errorTx": response["response_elem"]["ret_msg"],
                        },
                        "data": response["response_elem"]["result"],
                    }
                }
            except KeyError as err:
                response_with_header = {
                    "header": {
                        "ident": param_header["ident"],
                        "errorNum": 400,
                        "errorTx": f"Expected response from `{param_header['param1']}` don't follow general structure",
                    },
                    "data": f"The following key has not been found : {str(err)} as expected response."
                    #
                    # Fix: add another elif or change the invoked service response structure
                    #
                }
            #
            # I've been afraid of what if I don't put is_xml_out_ok
            # Lot of property that I can't handle now
            #
            raw_xml = dicttoxml.dicttoxml(
                response_with_header, attr_type=False, root=False
            )
            dom = parseString(raw_xml)  # type: Document
            xmlstr = dom.toprettyxml(indent="    ")
            xmlstr = xmlstr.replace('<?xml version="1.0" ?>\n', "")

            is_xml_out_ok = True
            self.response.payload = xmlstr

        if not is_xml_out_ok:
            xml_out = self.create_xml_return(
                param_header["ident"],
                errorNum,
                errorTx,
                value_result,
                name_tag,
                name_tag_1,
                SimpleProperty,
                sql_property,
                solde,
            )
            self.response.payload = xml_out
        logging.warning(
            f"{blueline_service_name} - OUTPUT: {param_header['param1']} KEY: {self.cid}"
        )