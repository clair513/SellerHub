"""
Sunindu Data Inc.
Scripted by: Alok Kumar
Date: 05-10-2018

INPUT: 'Payments' file data that has been previously parsed and partially structured by 'paymentsFile_parsing' script.
OUTPUT: Payments data as a Pandas DataFrame or TextParserself. Columns are occasionally renamed and mostly pre-processed for better readability and on-page visualization, if input matches with our internal records.
"""

# Importing required libraries:
import numpy as np
import pandas as pd
from datetime import datetime
from datetime import date
from datetime import time



# Segregating Returns month and day into separate columns:
def returns_month_day(data):
    """
    DOCSTRING: Overall generates 6 new column/labels. Creates 4 additional columns, as 'Returns Day', 'Returns Month', '' and '', that holds Month, Day, Return Quantity month-wise as well as day-wise.
    Additionally another column 'Week day/end' is created to determine if a return transaction day is a Weekday or Weekend. Then '' is created to compute Return quantity over Weekdays v/s Weekends.
    INPUT:
    > 'data' : Only accepts Pandas DataFrame or TextParser, structured by 'paymentsFile_parsing' script.

    OUTPUT:
    Pandas DataFrame with modified column names as per our internal records.
    """
    # Determining Month name and day of week for each transaction:
    data["Returns Day"] = data["return_date"].dt.day_name()
    data["Returns Month"] = data["return_date"].dt.month_name()
    # Computing Total Return Quantity per 'Returns Month', and then by (Month --> Day):
    data["Return Quantity per Month"] = data.groupby("Returns Month")["Return Quantity"].transform("sum")
    data["Return Quantity per Day of Week"] = data.groupby(["Returns Month", "Returns Day"])["Return Quantity"].transform("sum")
    # Ascertaining whether return day is Weekday or Weekend:
    data["Week day/end"] = np.nan
    for i,v in data["Returns Day"].iteritems():
        if v in ["Saturday", "Sunday"]:
            data.loc[i, "Week day/end"] = "Weekends"
        else:
            data.loc[i, "Week day/end"] = "Weekdays"
    # Calculating Returns per (Month --> Week day/end):
    data["Return Quantity on Weekday/end"] = data.groupby(["Returns Month", "Week day/end"])["Return Quantity"].transform("sum")
    return data


def returns_per_date_sku(data):
    """
    DOCSTRING: Computes total number of returned quantities ('Return Quantity') per Return date ('returns_date'), thus adding new column as 'Returns per Date'.
    Calculates total return quantity for each SKU, as 'Total SKU Returns'.
    INPUT:
    > 'data' : Only accepts Pandas DataFrame or TextParser.

    OUTPUT:
    Pandas DataFrame with additional columns as specified in Docstring.
    """
    # Calculating date-wise Total Return Quantity over entire time-frame:
    data["Return Quantity per Date"] = data.groupby("return_date")["Return Quantity"].transform("sum")
    # Calculating total return for each SKU over each month:
    data["Monthly Return Quantity per SKU"] = data.groupby(["Returns Month","SKU"])["Return Quantity"].transform("sum")

    return data
