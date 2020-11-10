#!/usr/bin/env python3

import argparse
import sys
import datetime
import time
import os
import subprocess
import re
from lxml import etree
from configparser import ConfigParser

# Imports the config file
try:
	config_name = 'config.ini'
	config = ConfigParser()
	config.read(os.path.join(os.path.dirname(__file__),config_name))
except:
	print("config.ini was not found, exiting...")
	exit()

sys.path.insert(0,os.path.expanduser(config.get('recon-ng','path')))
from recon.core import base
from recon.core.framework import Colors

#Pip packages that are needed for the script to work
package_list = [
	'dnspython',
	'lxml',
	'shodan'
	]

	
def run_module(reconBase, module, domain):
	recon = module_load(reconBase, module)
	recon._do_options_list('')
	#recon._do_options_set("SOURCE " + domain)
	recon.do_run(None)
	

def run_recon(domains):
	stamp = datetime.datetime.now().strftime('%Y_%m_%d-%H:%M')
	if args.workspace:
		wspace = args.workspace
	else:
		wspace = domains[0]+ '-' +stamp
		
	previous_path = os.getcwd() + '/'
	os.chdir(os.path.expanduser(config.get('recon-ng','path')))

	reconb = base.Recon()
	options = [base.Mode.CLI, wspace]
	reconb.start(*options)
	reconb.onecmd("options set TIMEOUT 100")
	
	os.chdir(previous_path)
	previous_path = None
	
	module_list = [
		'recon/companies-multi/whois_miner',
		'recon/domains-hosts/hackertarget',
		'recon/domains-hosts/brute_hosts',
		'recon/domains-hosts/binaryedge',
		'recon/hosts-hosts/ipinfodb',
		'recon/hosts-ports/shodan_ip',
		'recon/hosts-ports/binaryedge',
		'recon/contacts-credentials/hibp_breach',
		'recon/contacts-credentials/hibp_paste'
		]
	
	# Syncs the API keys
	sync_keys(reconb)
		
	# Adds domains into the domain database in recon-ng
	for domain in domains:
		reconb.insert_domains(domain=domain, mute=True)
		
	## Start of theHarvester Selection 
	
	# This will run and import theHarvester
	if args.theHarvester or \
	config.getboolean('theHarvester', 'always_run'):
		run_theHarvester(reconb, domains[0])
		
	# This will parse the harvester output files
	if args.harvester_xml_file:
		parse_harvester(reconb, args.harvester_xml_file)
		
	# This will import the seperate host and email files from theHarvester 
	if args.email_file and args.host_file:
		load_hosts(reconb, args.host_file)
		load_email(reconb, args.email_file)
	
	## End of theHarvester Selection	
		
	# Runs the linkedin module if there is a specified company
	if args.companies:
		run_linkedin(reconb, args.companies)
		
	# Runs mangle if needed
	if (args.harvester_xml_file or (args.email_file and args.host_file)\
	or args.companies or args.theHarvester):
		if args.pattern:
			for domain in domains:
				run_mangle(reconb, domain, args.pattern)
		
	# Runs each module inside the module list
	for module in module_list:
		#print("Module: %s, Domain: %s" % (module, domain))
		run_module(reconb, module, domain)
					
	#Exports the DB to an excel file	
	export_Excel(reconb, args.export)


# Updates the api keys stored in recon-ng
def sync_keys(reconBase=''):
	options = config['recon-ng']
	imput = False
	if reconBase == '':
		imput = True
		reconBase = base.Recon()
		recon_options = [base.Mode.CLI]
		reconBase.start(*recon_options)
			
	if (not imput and options.getboolean('key_auto_update'))\
	or imput:
		recon = reconBase
		recon_keys = recon._query_keys('select * from keys')
		config_keys = config['apiKeys']
		config_changed = False
		
		# Handles if no modules has been loaded beofre running
		if recon_keys == []:
			for config_key in config_keys.items():
				recon.add_key(config_key[0], config_key[1])
						
		# This will deal with most other scenarios
		else:
			# Compares the recon-ng keys to the config keys
			for recon_key in recon_keys:
				for config_key in config_keys.items():
					if recon_key[0] == config_key[0]:
					
						# This section runs if one of the keys is blank, but
						# not both of them are blank
						if (recon_key[1] == '' or config_key[1] == '') \
						and not(recon_key[1] == '' and config_key[1] == ''):
							if recon_key[1] == '':
								recon.add_key(config_key[0], config_key[1])
								config_changed = True
							elif config_keys[recon_key[0]] == '':
								config_keys[config_key[0]] = recon_key[1]
								config_changed = True
								
						# This section runs if both files has a key, the keys
						# are not the same and the key_override_from_master
						# is set to true 
						elif (recon_key[1] != config_keys[recon_key[0]]) and \
						options.getboolean('key_override_from_master')\
						and not(recon_key[1] == '' and config_keys[recon_key[0]] == ''):
							if options.getboolean('key_master_config_file'):
								recon.add_key(config_key[0], config_keys[1])
								config_changed = True
							else:
								config_keys[config_key[0]] = recon_key[1]
								config_changed = True
								
			# Writed the changes to the ini file if there is an update	
			if config_changed:
				with open(dir_file(config_name), 'w') as configfile:
					config.write(configfile)
	# Clears variables from memeory				
	api_keys = None
	options = None
	config_changed = None

	
def run_theHarvester(reconbase, domain):
	theHarvester = config['theHarvester']
	previous_path = os.getcwd() + '/'
	filename = theHarvester['temp_filename']
	theHarvester_path = os.path.expanduser(theHarvester['path'])
	
	os.chdir(theHarvester_path)
	subprocess.run("\'{}theHarvester.py\' -b {} -d {} \
	-f {}".format(theHarvester_path, theHarvester['source'],\
	domain, "'" + previous_path + filename + ".'"), shell=True)
	os.chdir(previous_path)
	parse_harvester(reconbase, filename + '.xml')
	
	# Clears variables from memeory
	theHarvester_path = None
	previous_path = None
	filename = None

		
def parse_harvester(reconBase, filename):
	tree = etree.parse(filename)
	for element in tree.iter("email"):
		reconBase.insert_contacts(email=element.text)
	for element in tree.iter("hostname"):
		reconBase.insert_hosts(host=element.text)
	# Clears variables from memeory
	tree = None
	element = None

				
def load_email(reconBase, filename):
	recon = module_load(reconBase, "import/list")
	recon._do_options_set("FILENAME " + filename)
	recon._do_options_set("TABLE contacts")
	recon._do_options_set("COLUMN emails")
	recon.do_run(None)
	
	
def load_hosts(reconBase, filename):
	recon = module_load(reconBase, "import/csv")
	recon._do_options_set("FILENAME " + filename)
	recon._do_options_set("HAS-HEADER false")
	recon._do_options_set("CSV-0 hostname")
	recon._do_options_set("CSV-1 ip_address")
	recon._do_options_set("TABLE hosts" )
	recon.do_run(None)
	
	
def run_linkedin(reconBase, companies):
	for company in companies:
		reconBase.insert_companies(company=company)
	recon = module_load(reconBase, "recon/companies-contacts/bing_linkedin_cache")
	#recon._do_options_set("SOURCE " + domain)
	recon._do_options_set("LIMIT 1")
	recon.do_run(None)
	
	
def run_mangle(reconBase, domain, pattern):
	recon = module_load(reconBase, 'recon/contacts-contacts/mangle')
	recon._do_options_set("SOURCE " + domain)
	recon._do_options_set("PATTERN " + pattern)
	recon._do_options_set("MAX-LENGTH 60")
	recon.do_run(None)	


def export_Excel(reconBase, filename):
	recon = module_load(reconBase, 'reporting/xlsx')
	recon._do_options_set("filename " + filename)
	recon.do_run(None)


def module_load(reconBase, module):
	recon = reconBase._do_modules_load(module)
	if recon == None:
		reconBase._install_module(module)
		reconBase._do_modules_reload('')
		recon = reconBase._do_modules_load(module)
	if recon != None:
		return recon
	else:
		print("Automatic installation of module %s failed. Please install the module manualy")


def dir_file(filename):
	return os.path.join(os.path.dirname(__file__),filename)


# Installs the required pip module for the recon-ng modules to work
def pip_package_install(pip_packages):
	for package in pip_packages:
		subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])


parser = argparse.ArgumentParser(
	description='Automation script for recon-ng')
parser.add_argument("-w", "--workspace", dest="workspace", metavar="<name>", help="name of workspace inside recon-ng")
parser.add_argument("-d", dest="filename", metavar='<filename>', type=argparse.FileType('r'), help="input file of domains (one per line)", default=None)
parser.add_argument("-p", dest="pattern", help='Pattern options: <fi>,<fn>,<mi>,<mn>,<li>,<ln>', default=None)
parser.add_argument("-c", '--company', action='append', dest='companies', help="name of the company")
parser.add_argument("-E", "--export", metavar='<filename>', dest='export', help="name of the export file, default is output.xlsx", default="output.xlsx")
parser.add_argument("domains", help="one or more domains", nargs="*", default=None)

# theHarvester argument group
theHarvester_group = parser.add_argument_group('theHarvester', 'Commands to interact with theHarvester, if installed.')
theHarvester_group.add_argument("--theHarvester", help="Run theHarvester with the domains again google, yahoo, duckduckgo, and bing", action='store_true')
theHarvester_group.add_argument("-H", "--harvest", metavar='<filename>', dest='harvester_xml_file', help="xml file from harvester")
theHarvester_group.add_argument("-e", dest="email_file", metavar='<filename>', type=argparse.FileType('r'), help="input file of emails from harvester", default=None)
theHarvester_group.add_argument("-i", dest="host_file", metavar='<filename>', type=argparse.FileType('r'), help="input file of hosts from harvester", default=None)

# Setup argument group
setup_group = parser.add_argument_group('Optional Setup', 'Run these to automate some setup.')
setup_group.add_argument("-k", "--keys", dest="keys", action='store_true', help="adds api keys from config file if present")
setup_group.add_argument("--pip", dest='pip', action='store_true', help="installs the required pip modules for the script to work")

args = parser.parse_args()

domainList = []

if args.export:
	if not args.export.endswith('.xlsx'):
		args.export = args.export + '.xlsx'
			
if args.keys:
	sync_keys()

if args.domains:
	domainList+=args.domains

if args.filename:
	lines = args.filename.readlines()
	lines = [line.rstrip('\n') for line in lines]
	domainList+=lines

if args.pip:
		pip_package_install(package_list)

if len(domainList) > 0:
	run_recon(domainList)
