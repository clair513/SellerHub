"""
Script# : 1

INPUT: 'Orders' raw Data File generated by Amazon Seller Central Portal for a particular Seller that has been fed as webpage input by registered User.
OUTPUT: Orders data as a Pandas DataFrame or TextParserself. Then renames columns for better readability, if they match our internal records.
"""

# Importing required libraries:
import pandas as pd

pd.set_option('display.width', 1000)
pd.set_option('colheader_justify', 'center')


# Assigning variable name to location of User specific 'Orders' file. Shall be taken care of in 'DASHBOARD AMZ Overview' View function:
dummy_file = "./static/datahub/orders.txt"

expected_columns = {'order-id':'Order ID', 'order-item-id':'Order Item ID','Purchase Date':'Purchase Date','Purchase Time':'Purchase Time','Payment Date':'Payment Date','Payment Time':'Payment Time','buyer-email':'Email','buyer-name':'Name','buyer-phone-number':'Phone No.','sku':'SKU','product-name':'Product','quantity-purchased':'Purchase Quantity','currency':'Currency','item-price':'Item Price','item-tax':'Item Tax','shipping-price':'Shipping Price','shipping-tax':'Shipping Tax','ship-service-level':'Shipping SL','recipient-name':'Recipient Name','ship-address-1':'Shipping Address-1','ship-address-2':'Shipping Address-2','ship-address-3':'Shipping Address-3','ship-city':'City','ship-state':'State','ship-postal-code':'Pin Code','ship-country':'Country','ship-phone-number':'Shipping Phone No.','item-promotion-discount':'Item Discount','item-promotion-id':'Item Discount ID','ship-promotion-discount':'Shipping Discount','ship-promotion-id':'Shipping Discount ID','delivery-start-date':'Delivery Start Date','delivery-end-date':'Delivery End Date','delivery-time-zone':'Time Zone','delivery-Instructions':'Delivery Instructions','payment-method':'Payment Method','cod-collectible-amount':'COD Collectibles','already-paid':'Already Paid','payment-method-fee':'Payment Method Fee','is-business-order':'Is Business Order','purchase-order-number':'Purchase Order No.','price-designation':'Price Designation','fulfilled-by':'Fulfilled By','purchase-date':'Purchase UTC DateTime','payments-date':'Payment UTC DateTime'}

"""
[INFO] Dynamic List of reformed Column names are documented below only for future reference and holds no impact on code execution:-

new_ColumnNames = ['Order ID', 'Order Item ID', 'Purchase UTC DateTime', 'Payment UTC DateTime', 'Email', 'Name', 'SKU', 'Product', 'Purchase Quantity', 'Currency', 'Item Price', 'Item Tax', 'Shipping Price', 'Shipping Tax', 'Shipping SL', 'Recipient Name', 'Shipping Address-1', 'Shipping Address-2', 'City', 'State', 'Pin Code', 'Country', 'Shipping Phone No.', 'Item Discount', 'Item Discount ID', 'Shipping Discount', 'Payment Method', 'Payment Method Fee', 'Is Business Order', 'Fulfilled By', 'Purchase Date', 'Purchase Time', 'Payment Date', 'Payment Time', 'Purchase Day', 'Payment Day', 'Purchase Hour', 'Payment Hour', 'Selling Price', 'Discounts', 'Addl. Charges', 'Phase of Day', 'Total Earning', 'States', 'Month', 'Holiday', 'Week day/end', 'Purchase Quantity per Day', 'Purchase Quantity per Month', 'Total Earnings per Day', 'Total Earnings per Month', 'Monthly SKU Sold', 'Single/Bucket/Bulk', 'Reformed State', 'Reformed City', 'Metro/Premium City', 'Repeat/New Buyer', 'On Promotion', 'Phone No.', 'COD Collectibles']
"""


## Parses webpage input file to generate Pandas DataFrame:
def file_parser(filepath = dummy_file, sep = " ", delimiter = "\t"):
    """
    DOCSTRING:
    INPUT:

    > filepath : String (str). Optional but ideally expects an Object with a read() method (such as a file handle or StringIO).
    The string could also be a URL. Valid URL schemes include http, ftp, s3, and file.
    By default, auto-detects and parses one of our dummy Orders file in Amazon format.
    Accepted input file extensions include .CSV, .TSV and .TXT.
    > sep: String (str). Optional, and isn't expected to be modified unless critical. Powered by Python’s builtin parsing sniffer tool.
    In addition, separators longer than 1 character and different from '\s+' will be interpreted as regular expressions and will also force the use of the Python parsing engine. Note that regex separators are prone to ignoring quoted data. [Regex example: '\r\t'].
    > delimiter: String (str). Optional and isn't expected to be modified (Like setting to 'None') unless critical. Alternative argument name for previous argument sep.

    OUTPUT:

    Shall result into a Pandas DataFrame or TextParser.
    """
    # While parsing, taking care of 'purchase-date' and 'payments-date' columns and making 4 columns out of these 2 columns. Note that Amazon provides Datetime info in UTC format that shall be taken care of in 'ordersFile_preprocessing.time_of_day()':
    if filepath.lower().endswith((".txt", ".csv", ".tsv")):
        data = pd.read_csv(filepath, sep = sep, delimiter=delimiter, parse_dates=[0], infer_datetime_format=True, dtype={"is-business-order":"str"})
        temp_purchase_data = pd.DatetimeIndex(data["purchase-date"])
        temp_payments_data = pd.DatetimeIndex(data["payments-date"])
        data["Purchase Date"] = temp_purchase_data.date
        data["Purchase Time"] = temp_purchase_data.time
        data["Payment Date"] = temp_payments_data.date
        data["Payment Time"] = temp_payments_data.time
        return data
    else:
        return "Unknown file format detected. Supported formats include CSV, TSV and TXT. Kindly refer to our documentation for further assistance!"


## Validating current DataFrame Column Names against Column names in our records and accordingly renaming specific columns:
def columns_renamer(data, inplace=True):
    """
    DOCSTRING:
    INPUT:
    > data : Only accepts Pandas DataFrame or TextParser.
    > inplace: Optional Boolean (True/False) parameter. If set to False, only a copy of Dataframe column names get modified, which the function won't return. By default it is set to True and ideally not expected to be modified unless critical.

    OUTPUT:
    Pandas DataFrame with modified column names as per our internal records.
    """
    print("[INFO] Columns being modified are... ")
    for col in data.columns:
        # Dictionary copy method is used to avoid threaded coding issues during iteration:
        if col in list(expected_columns.copy().keys()):
            data.rename({col:expected_columns[col]}, axis=1, inplace=True)
            # Below line can be skipped in Prod env to avoid logging load:
            print(col, sep=" ,", end= "", flush=True)
        else:
            print("No column has been modified!")
    return data
