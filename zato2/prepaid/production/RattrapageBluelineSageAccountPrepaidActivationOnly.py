# -*- coding: utf-8 -*-

"""
Service that fetches all prepaid services transactions stored in Odoo
and transfers them to Sage accounts.
Transfered data are summed up by service and payment source.

TV:
- ussd_airtel
- ussd_orange
- ussd_telma

IZYTV:
- web_airtel
- web_orange
- web_telma
- bfv_visa

Internet:
- ussd_airtel
- bfv_visa

Full documentation can be found at :
http://wiki.malagasy.com/tech/si/dev/zato/BluelineSageAccountPrepaid

Updated by Alain on 2025-04-29
- compte general telma from 5200019 to 5300069
- add mvola and airtelmoney channels 
- add mvola and airtelmoney journal_code for sage
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import logging
import smtplib
import traceback
from datetime import datetime as dt
from datetime import timedelta, date
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import formatdate
from email import encoders
import time
from zato.server.service import Service

# librairies
import pytds
import tablib
from erppeek import Client
from six.moves.configparser import ConfigParser


class RattrapageBluelineSageAccountPrepaidActivationOnly(Service):
    @staticmethod
    def get_name():
        return "rattrapage.blueline.sage.account.prepaid.activation.only"

    class SimpleIO:
        request_elem = "sageprepaid_request"
        response_elem = "sageprepaid_response"
        # input_optional = ("transaction_date",)
        output_required = (
            "code",
            "status",
            "message",
        )
        default_value = None

    def handle(self):
        self.invoke_async(
            "blueline.track.service", {"service_name": self.get_name()}
        )
        
        logging.error('=============== |TEST MVOLA ACTIVATION to SAGE| =================')
        
        
        '''
        Define the date range for the transactions (January 1st to January 31st)
        start_date = date(2025, 2, 1)
        end_date = date(2025, 2, 21)
        '''
        start_date = date(2025, 6, 17)
        end_date = date(2025, 6, 17)
        
        # Loop through each date in date range
        transaction_date = start_date
        while transaction_date <= end_date:
            try:
                # Process transactions for the current date
                transactions_raw = self.get_transactions(transaction_date)
                transactions = self.prepare_transactions(transactions_raw)
                
                logging.warning("[BluelineSageAccountPrepaid] transactions found for {}".format(transactions))
                
                totals = self.set_totals(transactions)
                connection = self.connect_sage()

                if connection:
                    self.write_to_sage(totals, transaction_date, connection)
                    report_param = self._build_report_param(totals, transaction_date)
                    self._send_report(report_param, transaction_date)

                    # Log success for the current date
                    logging.info(
                        "[BluelineSageAccountPrepaid] Successfully processed transactions for {}".format(transaction_date)
                    )
                else:
                    logging.error(
                        "[BluelineSageAccountPrepaid] Unable to connect to Sage for {}".format(transaction_date)
                    )
            except Exception as e:
                # Log and handle errors for the current date
                logging.error(
                    "[BluelineSageAccountPrepaid] Error processing transactions for {}:\n{}".format(transaction_date, traceback.format_exc())
                )
                self._send_error_report(self.request.input, str(traceback.format_exc()))

            time.sleep(20)

            # Move to the next date
            transaction_date += timedelta(days=1)

        # Final response after processing all dates
        self.response.payload.code = 200
        self.response.payload.status = "OK"
        self.response.payload.message = {
            "message": "Processed all dates from April 1st to April 30th"
        }

    def get_transactions(self, transaction_date):
        """
        Fetches all transactions in Odoo for the given date.

        :param transaction_date: a Datetime
        :return: a list of the fetched transactions information in the following
                format:
                {
                    'product_type': 'TV',
                    'channel': 'ussd_telma',
                    'amount': 15000,
                    'operation_type': 'credit'
                }
        """
        next_day = transaction_date + timedelta(days=1)
        next_day_str = "{:04}-{:02d}-{:02d}".format(
            next_day.year,
            next_day.month,
            next_day.day,
        )
        transaction_date_str = "{:04}-{:02d}-{:02d}".format(
            transaction_date.year,
            transaction_date.month,
            transaction_date.day,
        )
        
        # Utilisation de la configuration d'Odoo du code principal
        CONFIG = ConfigParser()
        CONFIG.read("/etc/odoo/odoo-services.conf")
        odoo = Client(
            CONFIG.get("ODOO", "url"),
            db=CONFIG.get("ODOO", "database"),
            user=CONFIG.get("ODOO", "user"),
            password=CONFIG.get("ODOO", "password"),
        )
        
        logging.warning(
            "=======================  [BluelineSageAccountPrepaid][get_transactions] {} =================== ".format(transaction_date)
        )
        
        transactions = odoo.read(
            "blueline.account.prepaid.move",
            [
                # Need to modify the transaction date for manuel import
                # "transaction_date", ">=", "2025-02-01"
                ("transaction_date", ">=", transaction_date_str),
                ("transaction_date", "<", next_day_str),
                ("operation_type", "=", "credit"),
                ("transaction_type", "=", "Activation"),  # Changé de "Achat" à "Activation" comme dans le code principal
            ],
            fields=[
                "amount",
                "product_type",
                "channel",
            ],
        )
        logging.info(
            "[BluelineSageAccountPrepaid][get_transactions] "
            "Number of transactions from {} to {} (exclusive): {}".format(
                transaction_date_str,
                next_day_str,
                len(transactions),
            )
        )
        return transactions

    def prepare_transactions(self, transactions):
        """
        - Replace "3g" and "4g" with "internet".
        - Lower product_type.

        NB: For future references
        The account team decided to postpone the following functionalities.
        - Replace email adresses in "channel" with "espace_client"
        - Replace anything that isn't ussd, web payment or espace_client with
        "espace_vente".

        :param transactions: a list of the transactions dictionnaries
                {
                    'product_type': 'TV',
                    'channel': 'ussd_telma',
                    'amount': 15000,
                    'operation_type': 'credit'
                }
        :return: a list of the prepared transactions
        """
        prepared_transactions = []

        mvola_channels = [
            "mvola"
        ]

        channels = mvola_channels

        for transaction in transactions:
            if not transaction["product_type"]:
                continue  # Skip transactions without a product type

            if transaction["product_type"].lower() in ["4g", "3g"]:
                transaction["product_type"] = "internet"
            else:
                transaction["product_type"] = transaction["product_type"].strip().lower()

            if transaction["channel"] in channels:
                prepared_transactions.append(transaction)
        return prepared_transactions

    def set_totals(self, transactions):
        """
        Calculates the total amount for each (product_type, channel) pairs.
        :param transactions: a list of the transactions dictionnary:
                {
                    'product_type': internet
                    'channel': orange_money_izytv
                    'amount': 20000,
                }
        :return totals: a dict of the transactions per (product_type, channel) pair
                {
                    (internet, orange_money_izytv): 450000,
                }
        """
        totals = {}
        for transaction in transactions:
            product = transaction["product_type"].lower()
            channel = transaction["channel"].lower()
            amount = transaction["amount"]
            if (product, channel) not in totals:
                totals.update({(product, channel): amount})
            else:
                totals[(product, channel)] += amount
        logging.info(
            "[BluelineSageAccountPrepaid][set_totals] Transactions TOTAL {}\n".format(
                totals
            )
        )
        return totals

    def generate_ref(self, code_journal, product, transaction_date, operation):
        """
        Sage requires an unique reference in order to identify an entry.
        That reference is useful when querying for the entry.
        Reference length <= 13 char
        :param code_journal: str of the transaction's 'code journal'
        :param product: str of the product's name
        :param transaction_date: a Datetime
        :param operation: "credit" or "debit"
        :return: a str representing the entry's reference
                eg: BFV, internet, 2020-06-25, credit => BFinte200625C
        """
        date = "{:02d}{:02d}{:02d}".format(
            transaction_date.year,
            transaction_date.month,
            transaction_date.day,
        )[2:]
        return "{}{}{}{}".format(
            code_journal[:2], product[:4], date, operation[0].upper()
        )

    def connect_sage(self):
        """
        Connects to Sage using configuration file credentials.
        :return: a pytds connection or None
        """
        logging.info(
            "[BluelineSageAccountPrepaid] Establishing connection with SAGE...\n"
        )
        CONFIG = ConfigParser()
        CONFIG.read("/etc/sage/sage-services.conf")
        try:
            database = CONFIG.get("SAGE", "database").split(",")[1]
            connection = pytds.connect(
                server=CONFIG.get("SAGE", "host"),
                user=CONFIG.get("SAGE", "username"),
                password=CONFIG.get("SAGE", "password"),
                database=database,
            )
            logging.info(
                "[BluelineSageAccountPrepaid] Connection with Sage established.\n"
            )
            return connection
        except Exception as e:
            logging.error(
                "[BluelineSageAccountPrepaid] Error trying to connect with Sage. {}\n".format(
                    e
                )
            )
            return None

    def write_to_sage(self, totals, transaction_date, connection):
        """
        Creates/updates a Sage entry based on provided information.
        Creation and update are both handled through the same Sage script.
        If customer doesn't exist, Sage creates it, else it will update the
        existing entry with the new values.

        '@ec_intitule' <= 35 char

        For testing purposes, query the entry with:
        SELECT * FROM F_ECRITUREC where ref_import=<ec_refpiece>

        :param totals: a dict of the transactions per (product_type, channel)
            pair. Format is:
            {
                (internet, orange_money_izytv): 450000,
            }
        :param transaction_date: a Datetime
        :param connection: a pytds (Sage Connection) object.
        :return: None
        """
        queries = []
        transaction_date_fr = "{:02d}/{:02d}/{:04d}".format(
            transaction_date.day,
            transaction_date.month,
            transaction_date.year,
        )
        for transaction_pair, amount in totals.items():
            product = transaction_pair[0]
            operator = transaction_pair[1]
            accounts = self.get_accounts(operator, product)

            # credit operation
            queries.append(
                "execute usp_ins_ec_prepaid "
                "@jo_num='{code_j}',"
                "@ec_date='{date}',"
                "@ec_echeance='{date}',"
                "@ct_num='{partner_account}',"
                "@ec_intitule='{product}/encst {operator} du {date}',"
                "@ec_mt={amount},"
                "@cg_num='4110000',"
                "@cg_numcont='{account_gen}',"
                "@ec_piece='{ref}',"
                "@ec_refpiece='{ref}',"
                "@ec_sens='1'".format(
                    operator=accounts["operator"],
                    date=transaction_date_fr,
                    amount=amount,
                    code_j=accounts["code journal"],
                    ref=self.generate_ref(
                        accounts["code journal"],
                        product,
                        transaction_date,
                        "credit",
                    ),
                    partner_account=accounts["compte tiers"],
                    account_gen=accounts["compte général"],
                    product=product,
                )
            )
            # debit operation
            queries.append(
                "execute usp_ins_ec_prepaid "
                "@jo_num='{code_j}',"
                "@ec_date='{date}',"
                "@ec_echeance='{date}',"
                "@ct_num='',"
                "@ec_intitule='{product}/encst {operator} du {date}',"
                "@ec_mt={amount},"
                "@cg_num='{account_gen}',"
                "@cg_numcont='4110000',"
                "@ec_piece='{ref}',"
                "@ec_refpiece='{ref}',"
                "@ec_sens='0'".format(
                    operator=accounts["operator"],
                    date=transaction_date_fr,
                    amount=amount,
                    code_j=accounts["code journal"],
                    ref=self.generate_ref(
                        accounts["code journal"],
                        product,
                        transaction_date,
                        "debit",
                    ),
                    account_gen=accounts["compte général"],
                    product=product,
                )
            )

        with connection.cursor() as cur:
            for query in queries:
                logging.info(
                    "[BluelineSageAccountPrepaid][build_query]{}\n".format(
                        query
                    )
                )
                try:
                    cur.execute(query)
                    result = connection.commit()
                    logging.info(
                        (
                            "[BluelineSageAccountPrepaid][write_to_sage] "
                            "Sage insertion errors: {}\n"
                        ).format(result)
                    )
                except Exception as e:
                    if str(e) == "100010:Ecriture existant":
                        pass
                    else:
                        logging.error(
                            (
                                "[BluelineSageAccountPrepaid][write_to_sage] "
                                "Sage insertion errors: {}\n"
                            ).format(str(e))
                        )
                        self._send_error_report(query, e)

    def get_accounts(self, operator, product):
        """
        Gets "code journal", "compte général" and "compte tiers" of a given
        (product, operator) pair for Sage insertions.
        :param operator: a str of the operator of the transaction group.
            Only operator keywords will be considered, regardless of the plateform.
            eg: airtel_money_izytv => airtel
        :param product: a str of the product concerned by the transaction group
        :return: a dictionnary of the related accounts information
        """
        ACCOUNTS = {
            "mvola": {
                "code journal": "MVL",
                "compte général": "5300069",
                "compte tiers": {
                    "izytv": "C0000406350",
                    "tv": "C0000175293",
                    "internet": "C0000467939",
                    "carte telma x": "C0000467939",  # Added for Telma X
                },
            },
        }
        keywords = ACCOUNTS.keys()
        for keyword in keywords:
            if keyword.lower() == operator.lower():
                operator = keyword
        accounts = {
            "operator": operator,
            "code journal": ACCOUNTS[operator]["code journal"],
            "compte général": ACCOUNTS[operator]["compte général"],
            "compte tiers": ACCOUNTS[operator]["compte tiers"][product],
        }
        return accounts

    def _send_error_report(self, query, exception):
        """
        Sends an error report
        :param query: a string of the faulty query.
        :param exception: a string representation of the exception that
        :return : None
        """
        destinations = "dev@si.blueline.mg,integration@si.blueline.mg"
        subject = "[BluelineSageAccountPrepaid]Erreur d'écriture"
        content = (
            "service: {}\n\n"
            "query: {}\n\n"
            "result: {}".format(self.get_name(), query, exception)
        )
        self._send_email(destinations, subject, content)

    def _build_report_param(self, totals, transaction_date):
        """
        Builds the report data.
        :param totals: list of (product, operator)
        :param transaction_date: a Datetime
        :return: a list of dict, sorted by product name
        """
        report_param = []
        date_str = dt.strftime(transaction_date, "%d/%m/%y")
        for couple, total in totals.items():
            product = couple[0]
            operator = couple[1]

            accounts = self.get_accounts(operator=operator, product=product)
            label = "{product}/encst {operator} du {date}".format(
                product=product, operator=operator, date=date_str
            )

            operation = "credit"
            reference = self.generate_ref(
                code_journal=accounts["code journal"],
                product=product,
                transaction_date=transaction_date,
                operation=operation,
            )
            report = {
                "reference": reference,
                "intitule": label,
                "montant total": total,
                "code journal": accounts["code journal"],
                "compte general": "4110000",
                "contrepartie": accounts["compte général"],
                "compte tiers": accounts["compte tiers"],
                "operation": "1",
                "produit": product,
            }
            report_param.append(report)

            operation = "debit"
            reference = self.generate_ref(
                code_journal=accounts["code journal"],
                product=product,
                transaction_date=transaction_date,
                operation=operation,
            )
            report = {
                "reference": reference,
                "intitule": label,
                "montant total": total,
                "code journal": accounts["code journal"],
                "compte general": accounts["compte général"],
                "contrepartie": "4110000",
                "compte tiers": "-",
                "operation": "0",
                "produit": product,
            }
            report_param.append(report)
        report_param = sorted(report_param, key=lambda k: k["produit"])
        return report_param

    def _send_report(self, parameter_l, transaction_date):
        """
        Sends a transaction report.
        Zato's built-in email system doesn't support file attachments from
        existing file so it is bypassed in this function.
        :param parameter_l: a list of the queries parameters
        :param transaction_date: a Datetime
        :return: None
        """
        transaction_date = dt.strftime(transaction_date, "%d%m%y")
        headers = [
            "produit",
            "reference",
            "intitule",
            "montant total",
            "code journal",
            "compte general",
            "contrepartie",
            "compte tiers",
            "operation",
        ]
        prepared_data = []

        for query in parameter_l:
            data = [query[header] for header in headers]
            prepared_data.append(data)

        report = tablib.Dataset(*prepared_data, headers=headers)
        file_path = "prepaid_{}.xls".format(transaction_date)
        try:
            with open(file_path, "wb") as f:
                f.write(report.export("xls"))
            logging.info(
                "[BluelineSageAccountPrepaid] File report "
                "/opt/zato/env/server/{}.xls created.".format(file_path)
            )
        except Exception as e:
            self.send_error_report(
                operation="File report creation", error=str(e)
            )

        message = (
            "Veuillez trouver en attaché le rapport des insertions comptables "
            "des produits prépayés (TV, Internet, IzyTV) datant du {} .\n\n"
            "-----------------------------------------------------------------\n"
            "Cet email est généré automatiquement, merci de ne pas y répondre.\n"
            "Pour toute réclamation, veuillez contacter le 2012 ou "
            "support_n1@si.blueline.mg.".format(transaction_date)
        )
        sender = "zato3@si.blueline.mg"
        destinations = [
            "dev@si.blueline.mg",
            # "comptabilite@blueline.mg",
            # "integration@si.blueline.mg",
        ]

        msg = MIMEMultipart("related")
        msg[
            "Subject"
        ] = "SAGE | Rapport des insertions comptables prépayés du {}".format(
            transaction_date
        )
        msg["From"] = sender
        msg["To"] = ", ".join(destinations)
        msg["Date"] = formatdate(localtime=True)

        content = MIMEText(message, "plain", "utf-8")
        msg.attach(content)

        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(
            open("/opt/zato/env/server/{}".format(file_path), "rb").read()
        )
        encoders.encode_base64(attachment)
        attachment.add_header(
            "Content-Disposition", 'attachment; filename="{}"'.format(
                file_path
            )
        )
        msg.attach(attachment)

        smtp = smtplib.SMTP()
        smtp.connect("smtp.blueline.mg", port=10026)
        smtp.sendmail(sender, destinations, msg.as_string())
        smtp.quit()

        logging.info(
            "[BluelineSageAccountPrepaid] Email: '{}' sent to {}".format(
                msg["Subject"], destinations
            )
        )

    def _send_email(self, destinations, subject, content):
        self.invoke(
            "blueline.send.email",
            {
                "mail_to": destinations,
                "mail_from": "zato3@si.blueline.mg",
                "mail_text": content,
                "title": subject,
            },
            as_bunch=True,
        )
        logging.info(
            "[BluelineSageAccountPrepaid] Email '{}' sent to {}".format(
                subject, destinations
            )
        )