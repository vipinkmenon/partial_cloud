if exist {lock} (
    del lock -s -Q
)
copy /y NUL lock >NUL
start tshark -i 5 -f "ip host 169.254.77.77" -c 264 -w receivedata.pcap
del lock -s -Q
exit