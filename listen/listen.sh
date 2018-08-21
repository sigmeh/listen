#!/usr/bin/env bash
#
# Set tshark to capture on interface i
#
# listen.sh accepts interface as arg or
# sets it to default (wifi, en1 currently). 
#
# Usage:
# 	bash listen.sh [-i=interface] [gui]


this_dir="$(dirname ${BASH_SOURCE[0]})"

echo '--------------------------------------'
echo 'Listen v 0.1 June 2018'
echo 'Running listen.sh --> listen.py'
echo 'Current interface data from ifconfig:'
		
python $this_dir/mac.py		#this script prints interface/MAC data from ifconfig utility

gui=0	#gui flag initialized to zero
i=en1	#default interface set here

for j in "$@"
do
case $j in
    -i=*|--interface=*)
    i="${i#*=}"
    ;;
    gui)
    gui=1
    ;;
    *)
     echo "Warning: Unknown option: \"$j\" (Ignoring)."
    ;;
esac
done

#[[ $@ != '' ]] && i=$@ || i=en1		#en1 set as default interface if not arg-specified

echo Listen is set to collect on interface $i...

tshark -i $i -f "not stp" -l -V | python $this_dir/listen.py gui=$gui

#	NOTE on arguments:
#
#	-i sets interface
#	-f sets capture filter
#	-l flushes buffer on full packet capture
#	-V provides packet details