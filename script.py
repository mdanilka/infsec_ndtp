import pyshark 
import time
capture = pyshark.LiveCapture(interface='eth0') 
capture.sniff(timeout=0)
cnt={}
tm={}
w=open("suspicions_packets.txt","w");
w.close()
for packet in capture.sniff_continuously(): 
    w=open("file.txt","w"); 
    w.write(str(packet)); 
    w.close();
    w=open("packest.txt","a")
    w.write(str(packet));
    w.write("\n");
    w.close()
    ip_address="";
    try:
        ip=packet["ip"] 
        print("Source Address:",ip.src)
        ip_address=ip.src;
        print("Destination Address:",ip.dst) 
        print("IP Protocol:",ip.proto) 
    except: 
        try: 
            ipv6=packet["ipv6"] 
            print("Source Address:",ipv6.src) 
            ip_address=ipv6.src;
            print("Destination Address:",ipv6.dst) 
            print("IP Protocol:",ip.proto) 
        except: 
            print("No IP address detected") 
     
    print("Length:",len(packet)) 
    try: 
        if 'tcp' in packet:
            tcp=packet['tcp'] 
            print("Source Port:",tcp.srcport) 
            print("Destination Port:",tcp.dstport) 
            w=open("tcp_ports.txt","a")
            w.write(str(tcp.srcport)+ ' ' + str(tcp.dstport));
            w.write("\n");
            w.close()
        else:
            udp=packet['udp'] 
            print("Source Port:",udp.srcport) 
            print("Destination Port:",udp.dstport) 
            w=open("udp_ports.txt","a")
            w.write(str(udp.srcport)+ ' ' + str(udp.dstport));
            w.write("\n");
            w.close()
    except: 
        print("No Source and destination ports detected")
    try:
        cnt[ip_address]+=1;
    except:
        cnt[ip_address]=1;
    if(cnt[ip_address]>100 and time.time()-tm[ip_address]<0.01):
        print("Suspicion packet detected");
        w=open("suspicions_packets.txt","a");
        w.write(str(packet));
        w.write("\n")
        w.close()
    tm[ip_address]=time.time();
    print() 
    print()