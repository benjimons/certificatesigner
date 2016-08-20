#!/usr/bin/env python
#Author Ben McDowall
#CSR Signing and management script

from OpenSSL import crypto
import sys, time, datetime, calendar, os, zipfile, sqlite3, getpass
from time import gmtime, strftime
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.mime.text import MIMEText
from email import Encoders

mailserver = "127.0.0.1"
setting_O="YOUR COMPANY NAME HERE"
setting_C="US"
user_csr = sys.argv[1]
ca_private_key = "keystuff/private.key"
ca_certificate = "keystuff/ca.crt"
root_certificate = "keystuff/root.crt"
fromaddr = "Certificates <certificates@example.com>"
ccaddr = "Certificates <certificates@example.com>"
conn = sqlite3.connect('certificates.sqlite')
error=0

c = conn.cursor()

#Load Private Key
try:
	with open(ca_private_key, "r") as my_key_file:
	    my_key_text = my_key_file.read()
	user_passphrase = getpass.getpass()
	privatekey = crypto.load_privatekey(crypto.FILETYPE_PEM,my_key_text, user_passphrase)
	user_passphrase = ""
	print("Loaded Private Key Successfully")
except: 
	print("FATAL: Cannot load private key, check your passphrase is correct!")
	exit()

#Load CA Certificate
try:
        with open(ca_certificate, "r") as my_cert_file:
            my_cert_text = my_cert_file.read()
        cacertificate = crypto.load_certificate(crypto.FILETYPE_PEM,my_cert_text)
	print("Loaded CA Cert Successfully")
except:
        print("FATAL: Cannot load CA Certificate!")
	exit()

#Load the CSR

with open(user_csr, "r") as my_cert_file:
    my_cert_text = my_cert_file.read()
    try:
	    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, my_cert_text)
	    print("Loaded CSR Successfully")
	    print("CN: "+csr.get_subject().CN)
	    thiscn=csr.get_subject().CN
	    print("Organisation: "+csr.get_subject().O)
	    thiso=csr.get_subject().O
	    print("Organisational Unit: "+csr.get_subject().OU)
	    thisou=csr.get_subject().OU
	    print("Country: "+csr.get_subject().C)
	    thisc=csr.get_subject().C
	    print("State: "+csr.get_subject().ST)
	    print("Locality: "+csr.get_subject().L)

    except:
	    print("Unable to load the CSR :(");

    print("Checking CSR details match requirements")

    if(thiso!=setting_O):
	print("FATAL: Organisation name does not match specification: "+setting_O)
	error=1
    if(thisc!=setting_C):
	print("FATAL: Country name does not match specification: "+setting_C)
	error=1

if error==1:
	print("Criteria not met, certificate not generated")
	exit()
else:
	 print("Criteria met successfully")

#Calculate the validity periods of the signed certificate
user_period = raw_input("Enter a length (1-3yr): ")
user_requestor = raw_input("Enter Requestors Name: ")
user_contact_spg = raw_input("Enter Contact Email Address: ")
if user_period > 0:
	currenttime=time.gmtime(time.time())
	notBeforeVal = calendar.timegm(time.gmtime())
	notAfterVal = int(user_period)*31622400
	notAfterVal = notAfterVal+notBeforeVal
	
	notBeforeValtz = strftime("%Y%m%d%H%M%SZ", time.gmtime(notBeforeVal))
	notAfterValtz = strftime("%Y%m%d%H%M%SZ", time.gmtime(notAfterVal))
else:
  	print("Invalid year entered is invalid")

#get the next serial number
c.execute("SELECT MAX(id) from certs")

oldserial = c.fetchone()

serial_no =  oldserial[0]+1

#Sign the certificate
if error==0:
    newcert = "newcert/"+thiscn+".crt"
    print("Attempting to sign certificate")
    cert = crypto.X509()
    cert.set_serial_number(serial_no)
    cert.set_notBefore(notBeforeValtz)
    cert.set_notAfter(notAfterValtz)
    cert.set_issuer(cacertificate.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.sign(privatekey, 'sha1')
    domain_cert = open(newcert,"w")
    domain_cert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    domain_cert.close()
    print("Certificate Signed!")
    
    with open(newcert, "r") as new_cert_file:
            new_cert_text = new_cert_file.read()
    c.execute("INSERT into certs (cn, o, ou, start_date, end_date, certificate, requestor, spg_contact, serial) VALUES (?,?,?,?,?,?,?,?,?)", 
	    (thiscn, thiso, thisou, notBeforeVal, notAfterVal, new_cert_text, user_requestor, user_contact_spg, serial_no))

    conn.commit()

    zf = zipfile.ZipFile("SignedInternalCert.zip", "w")
    for dirname, subdirs, files in os.walk("newcert"):
	    zf.write(dirname)
	    for filename in files:
	        zf.write(os.path.join(dirname, filename))
    zf.close()

    print("Sending email with certificate to "+user_contact_spg)
    SUBJECT = "New Certificate for "+thiscn

    msg = MIMEMultipart()
    msg['Subject'] = SUBJECT 
    msg['From'] = fromaddr
    msg['To'] = user_contact_spg
    msg['CC'] = ccaddr
    part = MIMEBase('application', "octet-stream")

    part.set_payload(open("SignedInternalCert.zip", "rb").read())
    Encoders.encode_base64(part)
    
    part.add_header('Content-Disposition', 'attachment; filename="SignedInternalCert.zip"')

    bodytext = "Your certificate request for "+thiscn+" was accepted and signed, please see attached .zip file.\n\nThanks\nThe Certificate Team"
    partbodytext = MIMEText(bodytext, 'plain')    
    
    msg.attach(part)
    msg.attach(partbodytext)
    
    server = smtplib.SMTP(mailserver)
    server.sendmail(fromaddr, user_contact_spg+', '+ccaddr, msg.as_string())
    

    #send the file
    os.rename(newcert, "certs/"+thiscn+str(calendar.timegm(time.gmtime()))+".crt")
else:
    exit()
