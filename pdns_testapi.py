#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Francois Lacroix
# Written by Francois Lacroix <xbgmsharp@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Configure a domain using PDNS API
# https://github.com/PowerDNS/pdnsapi/
#
# Import the necessary libraries
# $ apt-get install python-json python-simplejson python-httplib2
import simplejson as json
import httplib2
import sys
from urlparse import urlparse
#Debug
from pprint import pprint

def testapi(o):
	username = o.username
	password = o.password
	host_uri = o.scheme + "://"+ o.hostname + ":" + str(o.port)
	url = "%s/servers/localhost/zones" % host_uri
	headers = {'content-type': 'application/json'}
	# Create a HTTP object, and use it to submit a POST request
	http = httplib2.Http() # add timout=10
	http.disable_ssl_certificate_validation=True # if using a webserver to force SSL
	http.add_credentials( username, password )
	#print url
	# -------------------------------------
	print "\nTest 0. List all zone"
	print "Sending..."
	try:
		response, content = http.request(url, 'GET', body="", headers=headers)
		print "Receiving..."
		if response["status"] == "200":
			pprint(json.loads(content))
		else:
			data = json.loads(content)
			print "Error retriving all zone. %s" % data["error"]
			#sys.exit(1)
	except:
		print "Unexpected error: %s %s" % (sys.exc_info()[0], sys.exc_info()[1])
		print "Oops! Something went wrong. Fix the URI and try again..."
		sys.exit(1)
	# -------------------------------------
	print "\nTest 1. Create a zone example.com"
	# With DNSSEC and no SOA
	payload = '{"kind":"Master", "name": "example.com", "masters": ["8.8.8.8"], "dnssec": true, "nameservers": ["ns1.example.com", "ns2.example.com"], "records": [ { "content": "1.1.1.1", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "a.example.com" }, { "content": "2a00:1450:4001:c02::5e", "disabled": false, "priority": 0, "ttl": 600, "type": "AAAA", "name": "a.example.com" }, { "content": "example.com", "disabled": false, "priority": 0, "ttl": 600, "type": "CNAME", "name": "www.example.com" }, { "content": "2.2.2.2", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "b.example.com" }]}'
	# With DNSSEC and custom SOA
	payload = '{"kind":"Master", "name": "example.com", "masters": ["8.8.8.8"], "dnssec": true, "nameservers": ["ns1.example.com", "ns2.example.com"], "records": [ { "content": "1.1.1.1", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "a.example.com" }, { "content": "2a00:1450:4001:c02::5e", "disabled": false, "priority": 0, "ttl": 600, "type": "AAAA", "name": "a.example.com" }, { "content": "example.com", "disabled": false, "priority": 0, "ttl": 600, "type": "CNAME", "name": "www.example.com" }, { "content": "2.2.2.2", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "b.example.com" }, {"content": "ns1.example.com hostmaster.example.com 2014051901 10800 3600 604800 3600", "disabled": false, "name": "example.com", "priority": 0, "ttl": 3600, "type": "SOA"}]}'
	# With custom SOA
	payload = '{"kind":"Master", "name": "example.com", "masters": ["8.8.8.8"], "nameservers": ["ns1.example.com", "ns2.example.com"], "records": [ { "content": "1.1.1.1", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "a.example.com" }, { "content": "2a00:1450:4001:c02::5e", "disabled": false, "priority": 0, "ttl": 600, "type": "AAAA", "name": "a.example.com" }, { "content": "example.com", "disabled": false, "priority": 0, "ttl": 600, "type": "CNAME", "name": "www.example.com" }, { "content": "2.2.2.2", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "b.example.com" }, {"content": "ns1.example.com hostmaster.example.com 2014051901 10800 3600 604800 3600", "disabled": false, "name": "example.com", "priority": 0, "ttl": 3600, "type": "SOA"}]}'
	# With no SOA, should use default settings
	payload = '{"kind":"Master", "name": "example.com", "masters": ["8.8.8.8"], "nameservers": ["ns1.example.com", "ns2.example.com"], "records": [ { "content": "1.1.1.1", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "a.example.com" }, { "content": "2a00:1450:4001:c02::5e", "disabled": false, "priority": 0, "ttl": 600, "type": "AAAA", "name": "a.example.com" }, { "content": "example.com", "disabled": false, "priority": 0, "ttl": 600, "type": "CNAME", "name": "www.example.com" }, { "content": "2.2.2.2", "disabled": false, "priority": 0, "ttl": 600, "type": "A", "name": "b.example.com" }]}'
	print "Sending..."
	pprint(json.loads(payload))
	response, content = http.request(url, 'POST', body=payload, headers=headers)
	print "Receiving..."
	if response["status"] == "200":
		pprint(json.loads(content))
	else:
		data = json.loads(content)
		print "Error creating domain. %s" % data["error"]
		#sys.exit(1)

	# -------------------------------------
	print "\nTest 2. List zone example.com"
	url = "%s/servers/localhost/zones/example.com." % host_uri
	#print "Sending..."
	#pprint(payload)
	response, content = http.request(url, 'GET', body=payload, headers=headers)
	print "Receiving..."
	if response["status"] == "200":
		pprint(json.loads(content))
	else:
		data = json.loads(content)
		print "Error listing domain. %s" % data["error"]
		#sys.exit(1)

	# -------------------------------------
	print "\nTest 3. Add IPv4 record domain example.com"
	url = "%s/servers/localhost/zones/example.com." % host_uri
	print "Sending..."
	payload = '{ "rrsets": [ { "name": "ipv4.example.com", "type": "A", "changetype": "replace", "records": [ {"content": "1.2.3.4", "disabled": false, "name": "ipv4.example.com", "priority": 0, "ttl": 3600, "type": "A"} ] } ] }'
	pprint(json.loads(payload))
	response, content = http.request(url, 'PATCH', body=payload, headers=headers)
	print "Receiving..."
	if response["status"] == "200":
		pprint(json.loads(content))
		data = json.loads(content)
		for record in data['records']:
			if record['content'] == "1.2.3.4":
				print "Test 3. IPv4 OK"
	else:
		pprint(json.loads(content))
		print "Error adding IPv4 record. %s" % data["error"]
		sys.exit(1)

	# -------------------------------------
	print "\nTest 4. Add IPv6 record domain example.com"
	url = "%s/servers/localhost/zones/example.com." % host_uri
	print "Sending..."
	payload = '{ "rrsets": [ { "name": "ipv6.example.com", "type": "AAAA", "changetype": "replace", "records": [ { "name": "ipv6.example.com", "type": "AAAA", "priority": 0, "ttl": 3600, "content": "2a00:1450:4001:c02::aa", "disabled": false} ] } ] }'
	pprint(json.loads(payload))
	response, content = http.request(url, 'PATCH', body=payload, headers=headers)
	print "Receiving..."
	if response["status"] == "200":
		pprint(json.loads(content))
		data = json.loads(content)
		for record in data['records']:
			if record['content'] == "2a00:1450:4001:c02::aa":
				print "Test 4. IPv6 OK"
	else:
		data = json.loads(content)
		print "Error adding IPv6 record. %s" % data["error"]
		sys.exit(1)

	# -------------------------------------
	print "\nTest 5. Update IPv4 record domain example.com"
	url = "%s/servers/localhost/zones/example.com." % host_uri
	print "Sending..."
	payload = '{ "rrsets": [ { "name": "a.example.com", "type": "A", "changetype": "replace", "records": [ {"content": "4.3.2.1", "disabled": false, "name": "a.example.com", "priority": 0, "ttl": 3600, "type": "A"} ] } ] }'
	pprint(json.loads(payload))
	response, content = http.request(url, 'PATCH', body=payload, headers=headers)
	print "Receiving..."
	if response["status"] == "200":
		pprint(json.loads(content))
		data = json.loads(content)
		for record in data['records']:
			if record['content'] == "4.3.2.1":
				print "Test 5. IPv4 OK"
	else:
		data = json.loads(content)
		print "Error updating IPv4 record. %s" % data["error"]
		sys.exit(1)

	# -------------------------------------
	print "\nTest 6. Update IPv6 record domain example.com"
	url = "%s/servers/localhost/zones/example.com." % host_uri
	print "Sending..."
	payload = '{ "rrsets": [ { "name": "ipv6.example.com", "type": "AAAA", "changetype": "replace", "records": [ { "name": "ipv6.example.com", "type": "AAAA", "priority": 0, "ttl": 3600, "content": "2a00:1450:4001:c02::bb", "disabled": false} ] } ] }'
	pprint(json.loads(payload))
	response, content = http.request(url, 'PATCH', body=payload, headers=headers)
	print "Receiving..."
	if response["status"] == "200":
		pprint(json.loads(content))
		data = json.loads(content)
		for record in data['records']:
			if record['content'] == "2a00:1450:4001:c02::bb":
				print "Test 6. IPv6 OK"
	else:
		data = json.loads(content)
		print "Error updating IPv6 record. %s" % data["error"]
		sys.exit(1)

	# -------------------------------------
	print "\nTest 7. Remove domain example.com"
	url = "%s/servers/localhost/zones/example.com." % host_uri
	print "Sending..."
	payload = '{ "rrsets": [ { "name": "example.com", "changetype": "delete" , "changetype": "delete", "records": [] , "comments": [] } ] }'
	pprint(json.loads(payload))
	response, content = http.request(url, 'DELETE', body=payload, headers=headers)
	#response, content = http.request(url, 'DELETE', headers=headers)
	print "Receiving..."
	if response["status"] == "200" or response["status"] == "204":
		print "Test 7. Remove domain OK"
	else:
		data = json.loads(content)
		print "Error deleting domain. %s" % data["error"]
		sys.exit(1)

	print "All done."

def main():
	if len(sys.argv) < 2:
		sys.stderr.write('Usage: pdns_testapi.py SERVER_URI\n')
		sys.stderr.write('\thttp://a:changeme@localhost:8053/\n')
		sys.exit(1)
	o = urlparse(sys.argv[1])
	if (not o.username or not o.password or not o.hostname or not o.port or not o.scheme):
		sys.stderr.write('Error: URI schema invalid\n')
		sys.stderr.write('\thttp://a:changeme@localhost:8053/\n')
		sys.exit(1)
	testapi(o)

if __name__ == "__main__": main()

