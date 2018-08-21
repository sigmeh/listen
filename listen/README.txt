listen
listen.py
listen.sh

listen.py parses and saves interesting portions ot select tshark output

Usage:

	$ bash <path-to-file>/listen.sh
	
	or
	
	$ listen	# with a script in .bashrc like: "listen(){bash <path-to-file>/listen.sh}"
	

listen.sh is the pivotal script in this directory, which launches everything else. 
listen.sh launches tshark, whose buffered output gets flushed to listen.py following
each complete packet capture. 
listen.py listens continuously to stdin until keyboard interrupt, parsing each 
packet delivered from tshark's capture apparatus and storing the contents in
memory to identify repeated packets. 
A Packet object is created from each packet, whosed parsed fields and attributes
are used to populate pd (packet_data dictionary) with slimmed-down data. 
On keyboard interrupt (currently) the contents of pd (packet_data) are saved
(in cases where new data has been recorded during the capture session). 

The python web server within this application is intended to run for the purpose of 
delivering graphical output to a user-friendly environment (html page). 
The gui is under construction. 