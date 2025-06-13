from erppeek import Client
import logging

# Connection details
url = "http://odoo.malagasy.com:8069/"
database = "BluelineOdoo"
user = "patrice.razanakoto@staff.blueline.mg"
password = "cem@root"

# Initialize the client
client = Client(server=url, db=database, user=user, password=password)

date = {
    'before': '2025-02-13',
    'after': '2025-02-12'
}

def get_transaction():
    # Fetch transactions with specific fields
    transactions = client.read(
        "blueline.account.prepaid.move",
        [
            ("transaction_date", ">=", '2025-06-12'),
            ("operation_type", "=", "credit"),
            ("transaction_type", "=", "Activation"),
        ],
        fields=[
            'channel',
            'amount',
            'id_transaction_source',
            'users',
            'transaction_date',
            'product_type',
            'operation_type',
        ],
        # limit=3  # Limit the number of results
    )
    
    return transactions


def prepare_transactions(transactions):
    prepared_transactions = []

    izytv_channels = [
        # "orange_money_izytv",
        # "airtel_money_izytv",
        # "mvola_telma_izytv",
        # "bfv_sg_izytv",
        # "ussd_orange izytv"  # This is used to fix Orange IzyTV not exported to Sage
    ]
    
    tv_internet_channels = [
        # "ussd_orange",
        # "ussd_telma",
        # "ussd_airtel",
        # "bfv_sg_visa_mastercard",
    ]
    
    acces_banque_channels = [
        # "access_banque",
        # "accesbanque@blueline.mg"
    ]

    mvola_channels = [
        "mvola"
    ]

    airtel_channels = [
        # "airtelmoney"
    ]

    channels = izytv_channels + tv_internet_channels + acces_banque_channels + mvola_channels + airtel_channels

    for transaction in transactions:
        print(transaction)
        
        if not transaction["product_type"]:
            continue  # Skip transactions without a product type
        
        if transaction["product_type"].lower() in ["4g", "3g"]:
            transaction["product_type"] = "internet"
        else:
            transaction["product_type"] = transaction["product_type"].lower()

        if transaction["channel"] in channels:
            prepared_transactions.append(transaction)
    return prepared_transactions


def set_totals(transactions):
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


def get_accounts(operator, product):
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
        "airtel": {
            "code journal": "AIRT",
            "compte général": "5300033",
            "compte tiers": {
                "izytv": "C0000436748",
                "tv": "C0000172900",
                "internet": "C0000172900",
            },
        },
        "orange": {
            "code journal": "ORM",
            "compte général": "5300045",  # Updated from 5300035
            "compte tiers": {
                "izytv": "C0000414744",
                "tv": "C0000172901",
            },
        },
        "telma": {
            "code journal": "MVL",
            "compte général": "5300069",  # Updated from 5200019
            "compte tiers": {
                "izytv": "C0000406350",
                "tv": "C0000175293",
            },
        },
        "bfv": {
            "code journal": "VBFV",
            "compte général": "5300037",
            "compte tiers": {
                "izytv": "C0000415184",
                "internet": "C0000415184",
                "tv": "C0000415184",
            },
        },
        "acces": {
            "code journal": "VACB",
            "compte général": "5800038",
            "compte tiers": {
                "izytv": "C0000456425",
                "internet": "C0000456425",
                "tv": "C0000456425",
            },
        },
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
        "airtelmoney": {
            "code journal": "AIRT",
            "compte général": "5300043",
            "compte tiers": {
                "izytv": "C0000469117",
                "internet": "C0000469117",
            },
        },
    }
    keywords = ACCOUNTS.keys()
    for keyword in keywords:
        if keyword in operator:
            operator = keyword
    accounts = {
        "operator": operator,
        "code journal": ACCOUNTS[operator]["code journal"],
        "compte général": ACCOUNTS[operator]["compte général"],
        "compte tiers": ACCOUNTS[operator]["compte tiers"][product],
    }
    return accounts

# Main execution
transaction_raw = get_transaction()
transactions = prepare_transactions(transaction_raw)

print(f"Number of processed transactions: {len(transactions)}")

# for transaction in transactions:
    # print(transaction)

# print(prepare_transactions(transactions))

totals = set_totals(transactions)

print("Transaction totals:")
for couple, total in totals.items():
    product = couple[0]
    operator = couple[1]
    
    print(f'Product: {product}, Operator: {operator}, Total: {total}')
    
    try:
        accounts = get_accounts(operator=operator, product=product)
        print(f'  Accounts: {accounts}')
    except KeyError as e:
        print(f'  Error getting accounts for {operator}/{product}: {e}')
    
    print()  # Empty line for readability