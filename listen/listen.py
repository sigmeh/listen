#!/usr/bin/env python
'''
listen.py parses data piped from tshark via listen.sh, 
contained in the same directory as this script. 
tshark flushes its contents upon completion of each packet. 
A zero-length line (\n\n) signifies the end of a packet 
buffer, flushed from tshark using the '-l' argument. At this 
point, the packet is dissected (here) and a packet object is created, 
which gets dynamic attribute updates (via __setattr__() ) as 
each packet is parsed (using regular expressions). 
tshark must be installed in order to perform any of the following functions. 

Usage:
	$ bash <path-to-file>/listen.sh
	
	-or-
	
	$ listen  # provided that .bashrc contains something like: "listen(){ bash <path-to-file>/listen.sh }"

A list of attributes set dynamically can be accessed from 
each packet object as packet.user_set_attr_list
This facilitates iteration over the various values set
for each packet (which will differ for different types
of packets).

A packet_dict (packet.packet_dict) is formed from values 
derived from packet.user_set_attr_list. The packet_dict 
is hashed and saved in memory. Repeated entries that differ only by 
arrival time are then recorded by their arrival time alone, 
to avoid redundancy and save space (e.g., icmp and mdns are 
commonly repeated protocols on LAN).  

'''
print '-------------Begin listen.py----------------'
import sys
import os
import re
import json
import time
from bashcom import bashcom as bc 	# simple subprocess wrapper contained in same directory

this_dir = os.path.dirname(os.path.abspath(__file__))	# filesystem location of the running script
last_time = time.time()

''' Data objects '''
class packet_data(object):
	''' Create packet_data object from saved packet data in data folder '''
	def __init__(self):
		self.ip_dict = {}
		self.get_saved_data()
	
	def get_saved_data(self):
		ip_list = bc('ls %s/data' % this_dir).split()
		for ip in ip_list:
			self.ip_dict[ip] = {}
			hash_list = bc('ls %s/data/%s' % (this_dir, ip) ).split()
			for hash in hash_list:
				self.ip_dict[ip][hash] = {'el':[],'pd':{}, 'ch':False}	# truncated dict keys (epoch_list == el, packet_dict = pd, ch = "changed flag")
				

class metadata(object):
	def __init__(self):
		self.num_queries = 0
		self.num_responses = 0
		self.new_ip_list = []		

class Packet(object):
	''' Packet object stores parsed information from raw_packet (tshark output) '''
	def __init__(self):	
		''' Keep track of dynamically-added object attributes for subsequent iteration '''
		self.user_set_attr_list = []
		self.packet_dict = {}
	
	def add_dict(self, dict_to_add, **field):
		''' The **field kwarg is used to denote situations where there are multiple 
			incoming entries for a given dictionary key (e.g., Answers sections 
			responses to MDNS requests may contain multiple fields). The **field 
			kwarg adds a new 'field' list to the packet object to be populated with each 
			respective dictionary item generated in the raw dissection. 
		'''
		if field:	# Irregular dictionary flag/multiple incoming entries (see above)
			field = field.get('field')
			if field not in dir(self):
				self.__setattr__(field,[])
				self.user_set_attr_list.append(field)
			self.__getattribute__(field).append(dict_to_add)
			#self.__getattribute__(field).append(dict_to_add)
		else:		# Regular dictionary
			try: 
				for k in dict_to_add.keys():
					if not k in self.user_set_attr_list:
						self.__setattr__(k, dict_to_add[k])
						self.user_set_attr_list.append(k)
			except Exception as e:
				print 'Found exception adding dictionary'
				print e
				print dict_to_add
				print dir(dict_to_add)
				print self
				print dir(self)
	
	def add_protocol(self, protocol):
		''' Protocol is the last section of each tshark packet (encapsulated data) '''
		self.protocol = protocol
		self.user_set_attr_list.append('protocol')
	
	def add_header(self, header):
		pass

pd = packet_data() 
# Populate pd (packet_data) with previously saved data information
# pd represents all known src_ip and hash data. Each hash dictionary's fields
#  ( "epoch_list" == "el" and "packet_dict" == "pd" )
# become populated by new values parsed from incoming tshark data
# and are saved to disk following keyboard interrupt

'''	
##########
Data functions 1. Main data functions
##########
'''	
def get_raw_packet():
	''' Read contents of stdin until full packet capture and return complete packet '''	
	packet = ''	
	while 1: 
		line = sys.stdin.readline()
		packet += line
		if line == '\n': 	# Wait for end of packet 			
			return packet

def dissect(raw_packet):
	''' Split packet by section and extract relevant information from each section.
		Redefine incoming data as "raw_packet" (tshark-derived) and define new 
		object called 'packet'.
	'''
	packet = Packet()
	sections = [x.lstrip() for x in re.findall('(.+?)(?=\n\w|\n$|$|\s+$)', raw_packet.strip(), re.S)]

	packet_dict = {}
	for i,section in enumerate(sections):	
		'''	This larger loop explores each section and compares to a set of conditionals 
			to determine the relevant regular expressions to use in order to extract 
			interesting information from packet sections while discarding the rest. 
		'''	
		header = section.splitlines()[0].split(',')[0]
		
		''' The following loop attempts to extract a relevant encapsulated protocol from the section data. 
			This is typically the last section of the raw tshark packet, but sometimes an extra 
			section of hexdump data is tacked onto the end of the tshark packet (e.g., in the 
			case of ICMP replies). If the final section is being evaluated and it does not start with 
			an alphabetic character, the sections are traversed in reverse order until an appropriate
			header is discovered. For most packets, this reverse for-loop will break before actually looping.  
		'''	
		if i == len(sections) - 1:		#reached last section
			for s in sections[::-1]:	#traverse sections in reverse order
				if not re.search('^[A-z]', s): continue
				packet.add_protocol(s.splitlines()[0].split(',')[0])
				break
		
		'''	Simple series of conditionals to extract desired data from known sections 
			based on header identity; data gets added to packet.packet_dict
		'''
		try:
			if header.startswith('Frame'): 
				# Extract epoch time
				packet.frame = re.search('Frame (?P<frame>[^:]+)', section).group('frame')
				data_dict = re.search('Arrival Time: (?P<arrival_time>[^\n]*).*Epoch Time: (?P<epoch>\d+\.\d{3})', section, re.S).groupdict()
				packet.add_dict(data_dict)		
			elif header.startswith('Ethernet'):
				# Extract source and destination MAC addresses	
				data_dict = re.search('Src: (?P<src_mac2>\S+) \((?P<src_mac1>[^\)]+)\).+?Dst: (?P<dst_mac2>\S+) \((?P<dst_mac1>[^\)]+)\)', section).groupdict()
				packet.add_dict(data_dict)
			elif header.startswith('Internet Protocol Version'):	
				# Extract source and destination IP addresses	
				data_dict = re.search('Src: (?P<src_ip2>\S+) \((?P<src_ip1>[^)]+?)\), Dst: (?P<dst_ip>\S+)', section).groupdict()
				packet.add_dict(data_dict)		
			elif header.startswith('User Datagram Protocol'):
				# Extract source and destination port information
				data_dict = re.search('Src Port: (?P<src_port_name>[\S]+) \((?P<src_port_num>\d+)\).+?Dst Port: (?P<dst_port_name>\S+) \((?P<dst_port_num>\d+)\)',section).groupdict()
				packet.add_dict(data_dict)			
			elif header.startswith('Multicast Domain'):
				# Separate mdns by section (each new section is four spaces indented from left margin)
			
				mdns_sections = re.findall(' {4}(\w.+?)(?=\n {4}\w|$)', section, re.S)	
				mdns_dict = {}
				for mdns_section in mdns_sections:
				
					if mdns_section.startswith('Queries'):
						'''	Extract list (of tuples) for name,type in MDNS Query section.
							Formulate as dictionary list and update packet iteratively.						
							'field' is an optional kwarg sent to packet.add_dict(), which
							tells the packet object to create a new attribute list
							that will be composed of each dictionary passed to the object 
							(i.e., from a list of dicts)
						'''
						query_sections = re.findall('\n {8}(\S*?): type (\S*?),', mdns_section)
						query_dict_list = [{'name':x, 'type':y} for x,y in query_sections]
						for q in query_dict_list:
							packet.add_dict(q, field='Queries')
				
				
					elif mdns_section.startswith('Answers'):
						''' MDNS answer sections can be complicated with multiple responses in multiple formats. 
							In the following, Answers block is parsed by section. Each section is formulated as a 
							k:v dictionary based on line-by-line colon-separated data.
							Each new dictionary (one dict per section) is passed to the packet object to be incorporated 
							in a growing list of Answers entries, accessed via e.g., packet.Answers[0].Name      
							Sections having multiple identical keys (left-side of colon) are formulated as a list. 
						''' 
					
						answer_sections = re.findall('\n {8}(.+?)(?=\n {8}\w|\n$|$)', mdns_section, re.S)					
						for a in answer_sections:
							a_tuple_list = re.findall(' {12}([^:]+?): (.+)\n', a) #Each tuple in the list will be a key:value pair
							a_dict = {}
							for atl in a_tuple_list:
								if atl[0] in a_dict.keys():
									a_dict[atl[0]].append(atl[1])
								else:
									a_dict[atl[0]] = [atl[1]]
														
							packet.add_dict(a_dict, field='Answers') 
				
					elif mdns_section.startswith('Additional records'):
					
						pass					
			elif header.startswith('Domain Name System'):
				pass
			elif header.startswith('Address Resolution Protocol'):
				data_dict = re.search('.+? Sender IP address: (?P<sender_ip>\S+).+?Target IP address: (?P<target_ip>\S+)', section, re.S).groupdict()	
				packet.add_dict(data_dict)
			elif header.startswith('Internet Group Management Protocol'):
				data_dict = re.search('.*Type: (?P<type>.*?) \(.*Multicast Address: (?P<multicast_address>[^\s]+)', section, re.S).groupdict()
				packet.add_dict(data_dict)
			elif header.startswith('Bootstrap Protocol'):
				''' dhcp request '''
				try:
					data_dict = re.search('Client MAC address: (?P<client_mac2>[^ ]*) \((?P<client_mac1>[^)]*)\).*Requested IP Address: (?P<requested_ip>[^ ]*).*Host Name: (?P<host_name>.*?)\s', section, re.S).groupdict()			
				except:
					try:
						data_dict = re.search('Client MAC address: (?P<client_mac2>[^ ]*) \((?P<client_mac1>[^)]*)\).*Host Name: (?P<host_name>.*?)\s', section, re.S).groupdict()			
					except:																																						#\((?P<requested_ip1>[^)]+)\)
						try:
							data_dict = re.search('Client MAC address: (?P<client_mac2>[^ ]+) \((?P<client_mac1>[^)]+)\).+Requested IP Address: (?P<requested_ip2>[\S]+) \((?P<requested_ip1>[^)]+)\).+Vendor class identifier: (?P<vendor_class_id>[\S]+)',section,re.S).groupdict()							
						except:
							print 'Third exception found for bootstrap protocol...'
							raise
					
				packet.add_dict(data_dict)	
			elif header.startswith('802'):
				''' eapol protocol '''
				data_dict = {x:y for x,y in re.findall('\S\n    (\w[^:]+): (.*?)(?=\S\n    \w|$)', section, re.S)}	
				packet.add_dict(data_dict)		
			elif header.startswith('IEEE'):
				''' XID protocol, precedes dhcp '''
				data_dict = re.search('Source: (?P<source1>[^ ]+) \((?P<source2>[^)]+)\)', section).groupdict()
				packet.add_dict(data_dict)		
			elif header.startswith('Internet Control Message Protocol'):
				''' DO NOTHING; not much info in there '''
				pass
			elif header.startswith('OpenVPN'):
				''' DO NOTHING '''
				pass	
			elif header.startswith('Simple Service'):
				#data_dict = re.search('USN: (?P<usn>[^\n]+).*HOST: (?P<host>[^\n]+).*LOCATION: (?P<location>[^\n]+).*SERVER: ([^\n]+)', section, re.S).groupdict()
				data_dict = {x:y for x,y in re.findall('.*?\s(\w[^:]+?): ([^\n]*)',section,re.S)}
				packet.add_dict(data_dict)
			elif header.startswith('Logical-Link Control Basic Format XID'):
				pass
			elif header.startswith('Logical-Link Control'):
				pass
			elif header.startswith('NetBIOS Name Service'):
				print 'NetBIOS Name Service: pass'
			elif header.startswith('Secure Sockets Layer'):
				print 'Secure Sockets Layer section: pass'
			elif header.startswith('SKYPE'):
				data_dict = re.search('Src IP: (?P<skype_src_ip>[\S]+).*Dst IP: (?P<skype_dst_ip>[\S]+)', section, re.S).groupdict()
				packet.add_dict(data_dict)
			elif header.startswith('uTorrent Transport Protocol'):
				pass
			elif header.startswith('Link-local Multicast Name Resolution (query)'):
				pass
			else:
				print 'SECTION NOT PARSED!!!'
				print '#########################'
				print section
				print '##########END SECTION ##########'
				continue

		except Exception as e:
			print 'FOUND EXCEPTION:', e
			print 'Relevant section:', section
			print 'Timestamp:', packet.arrival_time
		
	packet_dict = {usa:packet.__getattribute__(usa) for usa in packet.user_set_attr_list if usa not in 'epoch,arrival_time'.split(',')}
	packet.packet_dict = packet_dict
	return packet
	

def unpack(packet):
	''' Unpack user-set attributes of packet object and print for user perusal '''
	for a in sorted(packet.user_set_attr_list):
		b = packet.__getattribute__(a)
		if type(b) is not list:
			print '%s : %s' % (a.ljust(17), b)
		else:
			print a			#attribute name (this is a list of dictionaries)
			for c in b:		#iterate over dictionaries
				for d in c.keys():
					if type(c[d]) is list and len(c[d]) == 1 and len(c[d][0]) < 3 or not re.search('[A-z]', d[0]) or d in 'TXT Length,Data length,Time to live'.split(','): continue 
					print '  %s : %s' % (d.ljust(17), c[d])

def save_packet(packet):
	'''	Generate hash value from packet.packet_dict for testing against saved data.
						
		Check this hash against previously-stored hash values and if there is a match, 
			then save only the timestamp (appended to 'epoch_list'). 
		Otherwise, create a new entry. 
		The data structure is:
		listen/
			data/
				src_ip1/
					hash_val1/
						packet_dict
						epoch_list
				src_ip2/
					hash_val1/
						packet_dict
						epoch_list
					hash_val2/
						packet_dict
						epoch_list
						
		The hash value is computed by the following expression:
			hash_val = hash(str(sorted([(x,packet.packet_dict.get(x)) for x in packet.packet_dict])))
		Neither the 'epoch' value nor 'arrival_time' value are part of the packet_dict, since 
			these values differ for each packet, precluding the use of this hash function and the 
			memory/time it is intended to save. 
	'''

	if len(packet.packet_dict) == 0:
		print 'Found empty packet_dict:'
		print 'len(packet.packet_dict) == 0'
		print dir(packet)
		print packet.user_set_attr_list
		return		
	
				#	Hash for computing dict changes; This value becomes the name of a directory to record identical, time-separated packets	
	h = 'h'+str(hash(str(sorted([(x,packet.packet_dict.get(x)) for x in packet.packet_dict])))) # (prepending 'h' avoids directories starting with '-' (which defines command line arguments))
	
	p = packet.packet_dict
	
	src_ip = p.get('sender_ip') or p.get('src_ip1')
	
	if not src_ip in pd.ip_dict.keys():
		pd.ip_dict[src_ip] = {}
		print 'Found new source ip: %s' % src_ip
	s = pd.ip_dict[src_ip]
	
	if not h in s.keys():
		s[h] = {'pd' : packet.packet_dict}
	if not s[h].get('el'):
		s[h]['el'] = []
	if not s[h]['el'] or s[h]['el'][-1] != packet.epoch:	# if epoch_list is empty or the last entry in epoch_list is different than the current
		s[h]['el'].append(packet.epoch)
		s[h]['ch'] = True
	
def write_final_data():
	''' On keyboard interrupt, write new data to file '''

	existing_src_ips = bc('ls %s/data' % this_dir).split()

	for src_ip in pd.ip_dict.keys():
		if not src_ip in existing_src_ips:
			bc('mkdir %s/data/%s' % (this_dir,src_ip))
		
		existing_hash_vals = bc('ls %s/data/%s' % (this_dir,src_ip)).split()
		s = pd.ip_dict[src_ip]
		
		for h in pd.ip_dict[src_ip].keys():

			p = s[h]['pd']
			e = s[h]['el']
			
			if not h in existing_hash_vals:
				bc('mkdir %s/data/%s/%s' % (this_dir, src_ip, h))
				bc('echo "%s" > %s/data/%s/%s/packet_dict' 	% (str( p ), this_dir, src_ip, h), shell=True)
				bc('touch %s/data/%s/%s/epoch_list' 		% (this_dir, src_ip, h))
				bc('echo "%s" > %s/data/%s/%s/epoch_list' 	% ( '\n'.join(e), this_dir, src_ip, h), shell=True)
			else:
				bc('echo "%s" >> %s/data/%s/%s/epoch_list' %( '\n'.join( [x for x in e if x] ), this_dir, src_ip, h), shell=True)
					
	
'''	
##########
Data functions 2. Accessory data functions (for development)
##########
'''	
def write_packet_stream():
	''' Read contents of stdin and add each packet to packet-file '''	
	packet = ''	
	c=0
	while 1: 
		line = sys.stdin.readline()
		packet += line
		if line == '\n': 	# Wait for end of packet 			
			#return packet
			with open('f1', 'a') as f:
				f.write(packet)
			c+=1
			packet = ''
			if c > 50: break

def get_saved_packet():
	with open('wireshark_eapol.txt','r') as f:
		return f.read()
'''	
##########
GUI functions
##########
'''	
def start_gui():
	import start
	start.main()
	#bc('python %s/start.py &' % this_dir, shell=True)


'''	
##########
Main functions
##########
'''	
def listen():
	''' Collect and parse packet stream and save data 
		tshark buffer gets flushed by listen.sh following each tshark packet's collection
		The raw_packet from tshark is then dissected (as "packet" object) and the data
		gets saved to file
	'''	
	while 1:
		raw_packet = get_raw_packet()
		if len(raw_packet) == 0:
			continue
		
		packet = dissect(raw_packet)	
		save_packet(packet)
	
def main():
	''' Begin listen: Collect and parse buffered packet stream and save data'''
	if 'gui=1' in sys.argv:
		print 'starting gui'
		print 'gui functionality not currently active by this method (sys argv)'
		#start_gui()
		# If GUI is in operation, then it must be started before running listen
		# because otherwise packets start to arrive on stdin, disrupting 
		# user-selected port specification. As such, a call back to listen()
		# must be completed at the end of the server process
		# (Or port specification is simply removed, which it was)
		#listen()
	#else:
	#start_gui()
	listen()

def main2():
	# For development, access this script directly as: $ python listen.py
	###
	file_to_open = 'f4'
	###
	''' Currently for development purposes only '''
	with open(file_to_open,'r') as f:
		raw_packet = f.read()
	packet = dissect(raw_packet)
	unpack(packet)	

###########################	
''' Start script '''
meta = metadata()
try:
	###########
	#if 'gui' in sys.argv:
	#	start_gui()
	main()
	###########
except KeyboardInterrupt:
	print
	print 'Writing new data...'
	write_final_data()
	
	print; print '...done. Goodbye!'	
###########################






# code graveyard below

'''
#Extra/development/currently-unused:


#Select num_packets_each_write below (packet data buffered before writing to file) 
num_packets_each_write = 1			# Select num packets to buffer here
npew = num_packets_each_write
packet_list = []
def collect_packet(packet):
	#	Collect packet data for saving. Accumulates "num_packets_each_write" number of packets 
	#	before write to minimize overhead, taken from global namespace
		
	global num_packets_each_write
	global npew
	global packet_list
	
	#print 'len(packet_list)',len(packet_list)		
	#print 'npew',npew
	if len(packet_list) <= num_packets_each_write:
		#print 'here'
		packet_list.append(packet)
		#print packet_list
	else:
		#print 'there'
		save_packets(packet_list)
		packet_list = []
		npew = num_packets_each_write
	npew += 1

def save_packets(packet_list):
	
	#print packet_list
	#packet_dicts = 
	for packet in packet_list:
		#packet_dict = {usat:packet.__getattribute__(usat) for usat in packet.user_set_attr_list}
		print packet.packet_dict
		#unpack(packet)
		#
		return
		
		with open('%/listen_data' % this_dir, 'w') as f:	
			f.write(packet.packet_dict)
		
		print '***'






def main3():	
	#write_packet_stream()
	#sys.exit()
	
	
	raw_packets = [x for x in get_saved_packet().split('\n\n') if not re.search('^\d', x)]
	# Ignore any entries starting with numbers (e.g., hex dumps beginning with line numbers#)
	
	for i,p in enumerate(raw_packets):
		if len(p) == 0: continue
		#print p
		packet = dissect(p)
		#print packet
		print dir(packet)
		print 'i:',i
		print 'p:',p
		print len(p)
		#continue
		#if i == 85:
		#	print len(packet.user_set_attr_list)
		print packet.epoch
		print packet.user_set_attr_list
		print len(packet.user_set_attr_list)


'''
	
##
##
##

'''
Receive json-encoded post requests from function 'post_data()' in static/proto.js

import cgi
import json

print

def test(data):
	with open('TEST','w') as f:
		f.write( str(data) )

def main():
	data = json.loads(cgi.FieldStorage()['package'].value)
	
	test('Running proto.py with the following data: %s' % data)
	
	
	result = data
	
	print json.dumps( result )
	
if __name__ == '__main__':
	main()
'''


'''
def get_saved_dict():
	ip_list = bc('ls %s/data' % this_dir).split()
	for ip in ip_list:
		print ip
		pd.ip_dict[ip] = {}
		hash_list = bc('ls %s/data/%s' % (this_dir, ip) ).split()
		print hash_list
		for hash in hash_list:
			print  hash
			pd.ip_dict[ip][hash] = {}
	#return ip_list
	
get_saved_dict()
'''

'''	
##########
Load saved data. 
This process will take longer as the data set gets larger (while the 
data loads, packets coming from tshark will not be collected). 
It may be necessary to specifically exclude certain high-volume
directories from loading, or more likely to scrap this and do it over. 
##########
'''	
#print_all = True
#print_all = False
#files,dirs,ftree = fw.walk(root='%s/data' % this_dir, max_depth=4, print_all=print_all)
#saved_dict = {}
'''
for src_ip in ftree.root.children:
	hash_list = ftree.root.children
	
	
	#print src_ip
	#print [x.name for x in src_ip.children]
	for y in src_ip.children:
		
		epoch_list, packet_dict = (z.name for z in y.children)
sys.exit()


class packet_data(object):
'''
	
'''
	def __init__(self):
		self.ip_dict = {}
		
	
	def add_ip(self, ip):
		self.ip_dict[ip] = {}
		#setattr(self, ip, {})
		#self.__setattr__(ip) = ip
	
	def add_hash(self, ip, hash):
		setattr(self.ip, 'hash', {'name':hash, 'epoch_list':[], 'packet_dict':{} })
		
		pass
		
class P(object):
	def __init__(self):
		pass

saved_dict = {}
pd = packet_data()

for j,i in enumerate(ftree.root.children):
	ip = i.name
	pd.ip_dict[ip] = {}
	#pd.add_ip(ip)
	for h in i.children:
		hash = h.name
		for c in h.children:
			print c.name
			#epoch_
			pd.ip_dict[ip][hash][c.name] = 
		#pd.add_hash(ip,hash)
	
		

print dir(pd)

	src_ip = i.name
	
	print 'src_ip',src_ip
	hash_list = [x.name for x in i.children]
	print 'hash_list',hash_list
	
	
	
	
	
	for h in hash_list:
		saved_dict[src_ip] = {'hash_list' : hash_list}	
'''	
		
'''

saved_dict =  	{x.name: { y.name : 
							{
								'epoch_list' : []
							} 
							for y in x.children for x in ftree.root.children
						
					}
				}
'''
#print saved_dict


'''
	if src_ip in pd.ip_dict.keys():
		s = pd.ip_dict[src_ip]
		if not hash in s.keys():
			s[hash] = {'epoch_list': [packet.epoch], 'packet_dict':packet.packet_dict}
		
		if hash in s.keys():
			if not s[hash].get('epoch_list'):
				s[hash]['epoch_list'] = []
			s[hash]['epoch_list'].append(epoch)
		else:
			s[hash]
			#pd.ip_dict[src_ip][hash_val]['epoch_list'].append(epoch)
		
	#if src_ip in saved_dict.keys():
	'''	
	
# BELOW IS OLD SUBPROCESS METHOD: POSSIBLY MAKING CPU GO OUT OF 
	#	CONTROL AFTER A PERIOD OF COLLECTING 10,000s OF PACKETS
	#	NEW CODE ABOVE ATTEMPTS TO PUT EVERYTHING INTO RAM.
	# 	IT WOULD BE POSSIBLE TO EXCLUDE SPECIFIC DIRECTORIES EASILY 
	#	(IF THEY ARE LARGE AND/OR UNINTERESTING)
	
'''
	
	saved_ip_list = bc('ls %s/data' % this_dir).split()
	#print saved_ip_list
	if src_ip not in saved_ip_list:
		bc('mkdir %s/data/%s' % (this_dir, src_ip))
	saved_hash_vals = bc('ls %s/data/%s' %(this_dir, src_ip)).split()
	if hash_val in saved_hash_vals:
		bc('echo "%s" >> %s/data/%s/%s/epoch_list' % (str(packet.epoch),this_dir,src_ip,hash_val),shell=True)
	else:
		bc('mkdir %s/data/%s/%s' % (this_dir, src_ip, hash_val))
		bc('echo "%s" > %s/data/%s/%s/packet_dict' % (str(packet.packet_dict),this_dir,src_ip,hash_val),shell=True)
		bc('echo "%s" > %s/data/%s/%s/epoch_list' %(str(packet.epoch),this_dir,src_ip,hash_val),shell=True)
	'''
