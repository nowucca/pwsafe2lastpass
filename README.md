Convert exported pwsafe (pwsafe.info) password vault into
lastpass sites and secure notes GEneric CSV files for import into Lastpass.

# Features
* Every pwsafe entry becomes a site (if a url is present) or a secure note otherwise
* PwSafe folders become lastpass folders correctly to multiple levels deep
* Automatically adds the right header to the lastpass output files for simpel import

# Usage

python pwsafe2lastpass.py

# Notes

Written February 2019.

I was using:
* pwsafe.info version 4.17 (https://app77.com/pwSafeMac)
* Lastpass Version 4.3.0 

Expects these files:
* (reads) pwsafe.csv  (a sample is provided)
* (writes) lastpass_sites.csv
* (writes) lastpass_secure_notes.csv

A sample template for a lastpass output file was provided:
https://helpdesk.lastpass.com/wp-content/uploads/Sample-Import-Spreadsheet.csv


