if exist {lock} (
    del lock -s -Q
)
copy /y NUL lock >NUL
tshark -i 2 -f "ip host 169.254.77.88" -c 264 -w receivedata.pcap
del lock -s -Q
exit