import struct

def eth_pkt_gen(in_file_name = None,out_file_name = None,offset = 0):

    magic_no = "\xD4\xC3\xB2\xA1"
    ver_maj = "\x02\x00"
    ver_min = "\x04\x00"
    time_corr = "\x00\x00\x00\x00"
    sigfis = "\x00\x00\x00\x00"
    snap_len = "\xFF\xFF\x00\x00"        #pcap file headers
    net_type = "\x01\x00\x00\x00"
    
    time_sec = "\x00\x00\x00\x00"
    time_ms = "\x00\x00\x00\x00"
    len_file = "\x0A\x04\x00\x00"
    len_actual = "\x0A\x04\x00\x00"

    src_addr = "\x20\x1A\x06\x08\x91\x9C"  #ethernet packet header
    dst_addr = "\xFF\xFF\xFF\xFF\xFF\xFF"
    eth_pkt_len = "\x08\00"
    
    crc = "\x00\x00\x00\x00" #default crc not used
    
    ip_ver  = "\x45"
    ip_dscp = "\x00"
    ip_len  = "\x03\xFC"
    ip_id   = "\x04\xCF"
    ip_flag = "\x40\x00"
    ip_ttl  = "\x3D"
    ip_prot = "\xFE"
    ip_crc  = "\x00\x00"
    ip_src  = "\xA9\xFE\x4D\x4D"
    ip_dst  = "\xFF\xFF\xFF\xFF"
   
    
    f = open(out_file_name,'wb')
    file_header = magic_no+ver_maj+ver_min+time_corr+sigfis+snap_len+net_type
    f.write(file_header)
    
    pkt_header = time_sec+time_ms+len_file+len_actual
    eth_header = dst_addr+src_addr+eth_pkt_len
    source = open(in_file_name,'rb')
    data = source.read() #read the file
    source.close() #close the file
    file_len = len(data) #find the total file size
    #print "total data = " + str(file_len)
    remain_len = file_len #store the remaining length for pkt formation
    start = offset

    if offset !=0:                        #for storing the file header in a temp file
        t = open(header_file,'wb')
        t.write(data[0:offset+1])
        t.close()

    while remain_len >= 1000:
        ip_crc = "\x00\x00"
        ip_header = ip_ver+ip_dscp+ip_len+ip_id+ip_flag+ip_ttl+ip_prot+ip_crc+ip_src+ip_dst
        a=struct.unpack('>HHHHHHHHHH',ip_header)
        ip_crc = calc_ip_crc(a)
        ip_header = ip_ver+ip_dscp+ip_len+ip_id+ip_flag+ip_ttl+ip_prot+ip_crc+ip_src+ip_dst
        f.write(pkt_header)
        f.write(eth_header)
        f.write(ip_header)
        f.write(data[start:start+1000])
        #f.write(crc)
        start += 1000
        remain_len -= 1000
    
    if remain_len > 0:
        remain_len = remain_len+20
        ip_len = struct.pack('h',remain_len)[1] + struct.pack('h',remain_len)[0]  
        total_pkt_len = 14+remain_len
        len_file = struct.pack('h',total_pkt_len) + "\x00\x00"
        ip_crc  = "\x00\x00"
        len_actual = len_file
        pkt_header = time_sec+time_ms+len_file+len_actual
        eth_header = dst_addr+src_addr+eth_pkt_len       
        ip_header = ip_ver+ip_dscp+ip_len+ip_id+ip_flag+ip_ttl+ip_prot+ip_crc+ip_src+ip_dst
        a=struct.unpack('>HHHHHHHHHH',ip_header)
        ip_crc = calc_ip_crc(a)
        ip_header = ip_ver+ip_dscp+ip_len+ip_id+ip_flag+ip_ttl+ip_prot+ip_crc+ip_src+ip_dst
        f.write(pkt_header)
        f.write(eth_header)
        f.write(ip_header)
        f.write(data[start:start+remain_len])
    #f.write(crc)
    
    f.close()

def eth_pack_decode(in_file_name = None, out_file_name = None):
    pkt_file = open(in_file_name,'rb')  #reopen the file
    data = pkt_file.read()
    pkt_file.close()
    g = open(out_file_name,'wb')
    file_len = len(data)
    print "total file size" + str(file_len)
    start = 54
    remain_len = file_len-54
    while remain_len >= 1030:
        g.write(data[start:start+1000])
        start += 1030
        remain_len -= 1030
    
    if remain_len != 0:
        g.write(data[start:start+remain_len])
    
    g.close()
    
def calc_ip_crc(a):
    tmp = a[0]+a[1]+a[2]+a[3]+a[4]+a[5]+a[6]+a[7]+a[8]+a[9]
    temp1 = struct.pack('>I',tmp)
    temp3 = struct.unpack('>HH',temp1)[0]
    temp4 = struct.unpack('>HH',temp1)[1]
    temp5 = temp3+temp4
    temp6 = 0xFFFF-temp5
    return struct.pack('>H',temp6)

import sys
if __name__ == "__main__":
    #if int(sys.argv[1]) == 0:
        eth_pkt_gen(sys.argv[1],sys.argv[2])
    #else:
    #    eth_pack_decode("ws_capt_file.pcap",sys.argv[2])
