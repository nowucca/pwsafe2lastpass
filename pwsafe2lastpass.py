##
## Convert exported pwsafe (pwsafe.info) password vault into
## lastpass sites and secure notes.
##

## Expects these files:
##     (reads) pwsafe.csv
##     (writes) lastpass_sites.csv
##     (writes) lastpass_secure_notes.csv
##

import csv

pwsafe_filename='pwsafe.csv'
site_filename='lastpass_sites.csv'
secure_notes_filename='lastpass_secure_notes.csv'

def read_pwsafe_value(row, index):
    if len(row) > index:
        return row[index]
    else:
        return ""

lp_rows=[]
sn_rows=[]


def debug_pwsafe_inputs():
    print("-------------------------------------")
    print("pw_grouptitle: " + pw_grouptitle)
    print("pw_username: " + pw_username)
    print("pw_password: " + pw_password)
    print("pw_url: " + pw_url)
    print("pw_created: " + pw_created)
    print("pw_modified: " + pw_modified)
    print("pw_record_modified: " + pw_record_modified)
    print("pw_history: " + pw_history)
    print("pw_email: " + pw_email)
    print("pw_notes: " + pw_notes)
    print("-------------------------------------")


def debug_lastpass_output():
    print("-------------------------------------")
    print("lp_url: " + lp_url);
    print("lp_username: " + lp_username)
    print("lp_password: " + lp_password)
    print("lp_name: " + lp_name)
    print("lp_extra: " + lp_extra)
    print("lp_grouping: " + lp_grouping)
    print("-------------------------------------\n")


with open(pwsafe_filename) as csvfile:
    readCSV = csv.reader(csvfile, delimiter='\t')
    for row in readCSV:
        # pwsafe

        pw_grouptitle= read_pwsafe_value(row, 0)
        pw_username= read_pwsafe_value(row, 1)
        pw_password=read_pwsafe_value(row, 2)
        pw_url=read_pwsafe_value(row, 3)
        pw_created=read_pwsafe_value(row, 4)
        pw_modified=read_pwsafe_value(row, 5)
        pw_record_modified=read_pwsafe_value(row, 6)
        pw_history=read_pwsafe_value(row, 9)
        pw_email=read_pwsafe_value(row, 10)
        pw_notes=read_pwsafe_value(row, 12)

        debug_pwsafe_inputs()

        #Prefer username but override with email
        tmp_username = pw_email if len(pw_username)==0 and len(pw_email)>0 else pw_username

        # Construct extra
        tmp_email = "email: "+pw_email+" " if len(pw_username)>0 and len(pw_email) >0 else ""
        tmp_notes = "notes: "+pw_notes+" " if len(pw_notes)>0 else ""
        tmp_history = "history: "+pw_history+" " if len(pw_history)>0 else ""
        tmp_audit = "audit: [C:"+pw_created+", M:"+pw_modified+", U:"+pw_record_modified+"]"

        # Grouptitle to name, grouping
        elements = pw_grouptitle.split(".") if len(pw_grouptitle)>0 else [];
        tmp_name = elements[len(elements)-1] if len(elements) >0 else "";
        tmp_grouping=""
        if len(elements)>1:
            tmp_grouping = "\\".join(elements[:len(elements)-1:]);

        is_note = len(pw_url) <=0

        # If there is no url, make this a generic note
        tmp_url="http://sn" if is_note else pw_url;


        # Lastpass
        lp_url=tmp_url
        lp_type=""
        lp_username=tmp_username
        lp_password=pw_password
        lp_hostname=""
        lp_extra = "".join([tmp_email,tmp_notes,tmp_history,tmp_audit])
        lp_name=tmp_name
        lp_grouping=tmp_grouping


        debug_lastpass_output()

        lp_row = [ lp_url, lp_type, lp_username, lp_password, lp_hostname, lp_extra, lp_name, lp_grouping]
        if is_note:
            sn_rows.append(lp_row)
        else:
            lp_rows.append(lp_row)

with open(site_filename, mode='w') as csvfile:
    lp_writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

    lp_writer.writerow(["url","type","username","password","hostname","extra","name","grouping"])
    for lp_row in lp_rows:
        lp_writer.writerow(lp_row)

with open(secure_notes_filename, mode='w') as csvfile:
    sn_writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
    sn_writer.writerow(["url","type","username","password","hostname","extra","name","grouping"])

    for sn_row in sn_rows:
        sn_writer.writerow(sn_row)

print("Wrote "+site_filename+ " and "+ secure_notes_filename)