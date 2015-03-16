# This module is intended to parse and decode the Chopper webshell traffic Requires 'http' parent module
# Sample usage: 
#./chopshop -f ../yourpcap.pcap "chop_ssl -k PrivateKey_RSA.key|http|webshell_chopper_decode"
#./chopshop -f ../yourpcap.pcap "http|webshell_chopper_decode"


from c2utils import packet_timedate, sanitize_filename, parse_addr
from optparse import OptionParser
import base64
import os, time, re, csv, datetime
import urlparse
import urllib2
import binascii

moduleName="webshell_chopper_decode"
moduleVersion="0.1"
minimumChopLib="4.0"

def module_info():
    return "Extract Chopper Webshell commands and output from HTTP traffic. Requires 'http' parent module."
def init(module_data):
    module_options = { 'proto': [{'http':''}]}
    parser = OptionParser()

    parser.add_option("-d", "--dict_output", action="store_true",
        dest="dict_output", default=False, help="Formats output to sets of dicts")
    parser.add_option("-c", "--commands_only", action="store_true", 
    	dest="commands_output", default=False, help="Only output chopper commands")
    parser.add_option("-o", "--outputs_only", action="store_true", 
    	dest="outputs_output",default=False, help="Only output chopper responses")
    parser.add_option("-x", "--extract_pe", action="store_true", 
    	dest="extract_pe",default=False, help="Attempts to extract pe files from session")

    (options,lo) = parser.parse_args(module_data['args'])

    module_data['dict_output'] = options.dict_output
    module_data['commands_output'] = options.commands_output
    module_data['outputs_output'] = options.outputs_output
    module_data['extract_pe'] = options.extract_pe

    return module_options

def handleProtocol(protocol):
	if protocol.type != 'http':
		chop.prnt("Error")
		return

	module_data = protocol.module_data

	timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.localtime(protocol.timestamp))
	data = {'request': protocol.clientData, 'response': protocol.serverData, 'timestamp': timestamp}
	
	chopper_commands, chopper_outputs = parseChopperCommands(data)

	if module_data['dict_output']:
		if chopper_commands is None:
			pass
		else:
			# Removing Blanks from Dict
			parsed_chopper_commands = dict((k, v) for k, v in chopper_commands.iteritems() if v is not None)
			chop.prnt(parsed_chopper_commands)
			chop.prnt(chopper_outputs)

	else:
		if chopper_commands is None:
			pass
		else:
			parsed_chopper_commands = dict((k, v) for k, v in chopper_commands.iteritems() if v is not None)

			if module_data['extract_pe']:
				filename = "chopper_extracted_file"
				filename_count = 1
				for value in parsed_chopper_commands.itervalues():
					if str(value).startswith("4D5A") and ("40000000" in value):
						binary_data = binascii.unhexlify(value)
						chop.savefile("%s-%i.bin" % (filename,filename_count), binary_data)
						chop.prnt("%s-%i.bin saved.." % (filename,filename_count))
						filename_count+=1
				for value in chopper_outputs.itervalues():
					if str(value).startswith("4D5A") and ("40000000" in value):
						binary_data = binascii.unhexlify(value)
						chop.savefile("%s-%i.bin" % (filename,filename_count), binary_data)
						chop.prnt("%s-%i.bin saved.." % (filename,filename_count))
						filename_count+=1

			if not module_data['outputs_output']:
				try:
					chop.prnt("[COMMAND] at "+parsed_chopper_commands['timestamp']+" on "+parsed_chopper_commands['host'])
				except:
					pass
				try:
					chop.prnt(parsed_chopper_commands['eval'])
				except:
					pass
				try:
					chop.prnt("[Z0 Parameter] - "+parsed_chopper_commands['z0'])
				except:
					pass
				try:
					chop.prnt("[Z1 Parameter] - "+parsed_chopper_commands['z1'])
				except:
					pass
				try:
					chop.prnt("[Z2 Parameter] - "+parsed_chopper_commands['z2'])
				except:
					pass

			if not module_data['commands_output']:	
				try:	
					chop.prnt("[RESPONSE] at "+chopper_outputs['timestamp'])
				except:
					pass
				try:
					chop.prnt("[Status] - "+chopper_outputs['status'])
				except:
					pass
				try:
					chop.prnt("[Ouput] - "+chopper_outputs['output'])
				except:
					pass
				else:
					pass

	return

def parseChopperCommands(data):

	timestamp = data['timestamp']
	request_body = str(data['request']['body']).lstrip()
	request_method = data['request']['method']
	request_host = data['request']['headers']['Host']
	request_uri = data['request']['uri']['path']
	request_useragent = data['request']['headers']['User-Agent']

	response_status = data['response']['status']
	response_body = data['response']['body']

	chopperCommandsDecoded, chopperOutputDecoded = {}, {}
	evalParameters, chopperCommandsDecoded = None, None
	z0,z1,z2,evalParameter = None, None, None, None

	# TODO: add parameter for chopper password?
	if request_method == 'POST':
		try:
			evalParameters = getEvalParameter(request_body)
			if evalParameters is not '':
				evalParameter = evalParameters 
		except:
			pass

		chopperZParameters = urlparse.parse_qs(request_body[request_body.find('&'):])

		try:
			# Try to decode z0 parameter as base64
			z0 = urllib2.unquote(''.join(chopperZParameters.get("z0"))).decode('base64')
			try:
				# Check if decoded parameter was actually orginally base64, if it wasn't then it probably won't be ascii.
				z0.decode('ascii')
			except UnicodeDecodeError:
				# If decoded parameter wasn't orginally base64 keep original value
				z0 = ''.join(chopperZParameters.get("z0"))
		except:
			try:
				# If decode as base64 fails, keep original value of z0
				z0 = ''.join(chopperZParameters.get("z0"))
			except:
				# If z0 doesn't exist then move on
				pass

		try:	
			z1 = urllib2.unquote(''.join(chopperZParameters.get("z1"))).decode('base64')
			try:
				z1.decode('ascii')
			except UnicodeDecodeError:
				z1 = ''.join(chopperZParameters.get("z1"))
		except:
			try:
				z1 = ''.join(chopperZParameters.get("z1"))
			except:
				pass

		try:
			z2 = urllib2.unquote(''.join(chopperZParameters.get("z2"))).decode('base64')
			try:
				z2.decode('ascii')
			except UnicodeDecodeError:
				z2 = ''.join(chopperZParameters.get("z2"))
		except:
			try:
				z2 = ''.join(chopperZParameters.get("z2"))
			except:
				pass

		if (z0 or z1 or z2 or evalParameter) is None:
			pass
		else:
			chopperCommandsDecoded = {'timestamp':timestamp, 'host':request_host, 'eval':evalParameter, 'z0':z0, 'z1':z1, 'z2':z2} 

		# Start Parsing Output
		if ("->|" or "|<-") in response_body:
			chopperOutputDecoded = {'output':response_body, 'status':response_status, 'timestamp':timestamp}

	return (chopperCommandsDecoded, chopperOutputDecoded)

def getEvalParameter(requestBody):
	result = re.findall(r'FromBase64String\("(.*?)"\)', requestBody)
	b64Encoded_EvalParameter = ''.join(result)

	try:
		b64Decoded_EvalParameter = urllib2.unquote(b64Encoded_EvalParameter).decode('base64')
	except:
		pass

	return b64Decoded_EvalParameter

def shutdown(module_data):
    return

def taste(tcp):
    return False

def teardown(tcp):
    return