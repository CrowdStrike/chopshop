moduleName="owa_ssl_decoder"
moduleVersion="0.1"
minimumChopLib="4.0"

from c2utils import packet_timedate, sanitize_filename, parse_addr
from optparse import OptionParser
from base64 import b64encode
import os, time, re, csv, datetime
from bs4 import BeautifulSoup
from urlparse import parse_qs, urlparse
import urllib
import warnings
import pprint 

def module_info():
	return "Parse OWA activity from PCAP. Requires 'chop_ssl' and 'http' parent module."

def init(module_data):
    module_options = { 'proto': [{'http': ''}] }
    # parser.add_option("-c", "--csv_output", action="store_true", 
    # 	dest="csv_output", default=False, help="Outputs data into CSV file")


    return module_options

def handleProtocol(chopp):
	if chopp.type != 'http':
		chopp.prnt("Error underlying trafic not http")
		return

	module_data = chopp.module_data
	timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.localtime(chopp.timestamp))
	data = {'request': chopp.clientData, 'response': chopp.serverData, 'timestamp': timestamp, 'addr': chopp.addr}
	parseOWAmessage(data)
	return

def parseOWAmessage(data):

	# email_parsed = {}

	if data['request']['body'] is None:
		del data['request']['body']
		del data['request']['body_hash']

	if data['response']['body'] is None:
		del data['response']['body']
		del data['response']['body_hash']

	del data['request']['truncated']
	del data['request']['body_len']
	del data['request']['hash_fn']

	del data['response']['truncated']
	del data['response']['body_len']
	del data['response']['hash_fn']


	timestamp = data['timestamp']
	src_ip = str(data['addr'][0][0])
	src_port = str(data['addr'][0][1])
	dest_ip = str(data['addr'][1][0])
	dest_port = str(data['addr'][1][1])


	request_method = data['request']['method']
	request_host = data['request']['headers']['Host']
	request_uri = data['request']['uri']['path']
	request_useragent = data['request']['headers']['User-Agent']
	response_status = data['response']['status']

	if 'body' in data['request']:
		request_body = str(data['request']['body']).lstrip()
		# Parse Authenication Username and Pass
		auth_regex = re.compile('destination=.+&username=.+&password=.+(?=&)').findall(request_body)
		if auth_regex:
			auth_string = urllib.unquote(auth_regex[0])
			auth_string_parsed = parse_qs(auth_string)
			
			email_server = auth_string_parsed['destination'][0]
			email_user = auth_string_parsed['username'][0]
			email_password = auth_string_parsed['password'][0] 

			chop.prnt("-----OWA Server and Account-----")
			chop.prnt("Server: "+email_server)
			chop.prnt("User: "+email_user+" Password: "+email_password)

	if 'body' in data['response']:
		response_body = data['response']['body']
		warnings.filterwarnings("ignore")

		# Begin Parsing of Email Content for Metadata
		try:
			# chop.prnt(response_body)
			email_searched_subjects_list = []
			parsed_html = BeautifulSoup(response_body, "lxml")	

			email_searched = parsed_html.body.find('span', attrs={'id':'spnSR'})

			if email_searched:
				# chop.prnt(email_searched)
				
				email_searched_subjects = parsed_html.body.findAll('div', attrs={'id':'divSubject'})

				for searched_subject in email_searched_subjects:	
					email_searched_subjects_list.append(searched_subject.string)

					chop.prnt("--------Searched Email Subjects----------")
					chop.prnt(src_ip+":"+src_port+" --> "+dest_ip+":"+dest_port)
					chop.prnt("Packet Timestamp: "+timestamp)

					for searched_email in email_searched_subjects_list:
						chop.prnt(searched_email)


			email_timestamp = parsed_html.body.find('span', attrs={'id':'spnSent'}).string
			email_subject = parsed_html.body.find('div', attrs={'id':'divConvTopic'}).string

			try:
				email_sender = parsed_html.body.find('div', attrs={'id':'divSn'}).string
				email_sender_address = parsed_html.body.find('span', attrs={'id':'spnFrom'})['title']
				email_from = email_sender + '<' + email_sender_address + '>'
			except TypeError:
				pass

			try:
				email_recipients_list = []
				email_recipients = parsed_html.body.findAll('span', attrs={'id':'spnR'})
				for recipient in email_recipients:
					email_recipients_list.append(recipient.string + '<' + recipient['title']+ '>')
			except TypeError:
				pass		

			chop.prnt("--------Accessed Email----------")
			chop.prnt(src_ip+":"+src_port+" --> "+dest_ip+":"+dest_port)
			chop.prnt("Packet Timestamp: "+timestamp)
			chop.prnt("Email Timestamp: "+email_timestamp)
			chop.prnt("Subject: "+email_subject)
			chop.prnt("From: "+email_from)
			chop.prnt("To: "+u' '.join(email_recipients_list).encode('utf-8').strip())
			
		except (UserWarning, AttributeError):
		# except Exception as inst:
		# 	chop.prnt(type(inst))    # the exception instance
		# 	chop.prnt(inst.args)     # arguments stored in .args
			pass
		
	return

def shutdown(module_data):
    return
