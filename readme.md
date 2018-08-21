<h4>listen</h4>
<h5>listen</h5>

listen uses python to parse the output of tshark, the command-line version 
of wireshark. The contents of the tshark buffer gets flushed with each complete
packet capture, where it is sent to listen.py to get dissected using regular expressions.
A python object is created and the data is saved according to hash values 
computed for identical packets that differ only by timestamp. 


Usage:

	$ bash path-to-listen-directory/listen/listen/listen.sh [args]
	
Better:

	$ listen [args]		# provided .bashrc contains a script like: "listen () { bash path-to-listen-directory/listen/listen/listen.sh $@ }"
	



The data structure for saved packet contents is as follows: 
	/path-to-dir/listen/
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





