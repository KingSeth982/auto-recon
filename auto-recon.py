#!/usr/bin/env python3.7

import argparse
import sys
import datetime
import time
import os
import subprocess
import re
from lxml import etree

try:
	from config import *
except:
	print("Config.py was not found")
	reconPath = "~/recon-ng/"

sys.path.insert(0,reconPath)
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
	stamp = datetime.datetime.now().strftime('%M:%H-%m_%d_%Y')
	if args.workspace:
		wspace = args.workspace
	else:
		wspace = domains[0]+stamp

	reconb = base.Recon()
	options = [base.Mode.CLI, wspace]
	reconb.start(*options)
	reconb.onecmd("TIMEOUT 100")
	
	module_list = [
		'recon/domains-hosts/hackertarget',
		'recon/domains-hosts/brute_hosts',
		'recon/domains-hosts/binaryedge',
		'recon/hosts-hosts/ipinfodb',
		'recon/hosts-ports/shodan_ip',
		'recon/hosts-ports/binaryedge'
		]
		
	# This 
	if args.harvestor_xml_file:
		parse_harvestor(reconb, args.harvestor_xml_file)
		
	# Adds domains into the domain database in recon-ng
	for domain in domains:
		reconb.insert_domains(domain=domain, mute=True)
		
	if args.companies:
		run_linkedin(reconb, args.companies)
		
	if args.email_file and args.host_file:
		load_hosts(reconb, args.host_file)
		load_email(reconb, args.email_file)
		if args.pattern:
			for domain in domains:
				run_mangle(reconb, domain, args.pattern)
	
	# Runs each module inside the module list
	for module in module_list:
		#print("Module: %s, Domain: %s" % (module, domain))
		run_module(reconb, module, domain)
			
	#Exports the DB to an excel file	
	export_Excel(reconb, args.export)

#Adds key for the config file if there is one present
def add_keys():
	reconBase = base.Recon()
	options = [base.Mode.CLI]
	reconBase.start(*options)
	for api_keys in keys:
		if not api_keys[1] == '':
			reconBase.onecmd("keys add %s %s" % (api_keys[0], api_keys[1]))
	
			
def parse_harvestor(reconb, filename):
	tree = etree.parse(filename)
	for element in tree.iter("email"):
		reconb.insert_contacts(email=element.text)
	for element in tree.iter("hostname"):
		reconb.insert_hosts(host=element.text)
				
def load_email(reconb, filename):
	recon = module_load(reconBase, "import/list")
	recon._do_options_set("FILENAME " + filename)
	recon._do_options_set("TABLE contacts")
	recon._do_options_set("COLUMN emails")
	recon.do_run(None)
	
	
def load_hosts(reconb, filename):
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
	recon._do_options_set("MAX-LENGTH 40")
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
	

# Installs the required pip module for the recon-ng modules to work
def pip_package_install(pip_packages):
	for package in pip_packages:
		subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

parser = argparse.ArgumentParser(
	description='Automation script for recon-ng')
parser.add_argument("-w", "--workspace", dest="workspace", metavar="<name>", help="name of workspace inside recon-ng")
parser.add_argument("-d", dest="filename", metavar='<filename>', type=argparse.FileType('r'), help="input file of domains (one per line)", default=None)
parser.add_argument("-e", dest="email_file", metavar='<filename>', type=argparse.FileType('r'), help="input file of emails from harvester", default=None)
parser.add_argument("-i", dest="host_file", metavar='<filename>', type=argparse.FileType('r'), help="input file of hosts from harvester", default=None)
parser.add_argument("-p", dest="pattern", help="pattern to whatever matches the emails seen from harvester", default=None)
parser.add_argument("-H", "--harvest", metavar='<filename>', dest='harvestor_xml_file', help="xml file from harvestor")
parser.add_argument("-l", '--linkedin', action='append', dest='companies', help="name of the compaony to be searched on linkedin")
parser.add_argument("-E", "--export", metavar='<filename>', dest='export', help="name of the export file, default is output.xlsx", default="output.xlsx")
parser.add_argument("--pip", dest='pip', action='store_true', help="installs the required pip modules for the script to work")
parser.add_argument("domains", help="one or more domains", nargs="*", default=None)
parser.add_argument("-k", "--keys", dest="keys", action='store_true', help="adds api keys from config file if present")

args = parser.parse_args()

domainList = []

if args.export:
	if not args.export.endswith('.xlsx'):
		args.export = args.export + '.xlsx'
		
		
if args.keys:
 add_keys()

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
