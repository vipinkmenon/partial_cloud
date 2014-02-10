python ..\scripts\pktgen.py 0 lena.bmp lena.pcap
bittwist -i 5 req.pcap
bittwist -i 5 config.pcap
bittwist -i 5 bs_done.pcap
bittwist -i 5 lena.pcap
bittwist -i 5 data_done.pcap
start tshark -i 5 -f "ip host 169.254.77.77" -c 264 -w receivedata.pcap
timeout 4
bittwist -i 5 data_req.pcap
echo done....