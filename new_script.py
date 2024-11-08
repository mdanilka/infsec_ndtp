import time
import pyshark
import requests
import json
API_URL = 'https://api.telegram.org/bot'
BOT_TOKEN = '7863723299:AAHZvETLbDOMOZPSrnFQpg2umb7F3P4wbTc'
chat_id=1077211564
capture = pyshark.LiveCapture(interface='eth0') 
capture.sniff(timeout=0)
cnt={}
tm={}
reply_id={}
w=open("suspicions_packets.txt","w");
w.close()
def wq(data,ip_address):
    document={'document': open("packet.txt", 'rb')}
    #requests.get(f'{API_URL}{BOT_TOKEN}/sendMessage?chat_id={chat_id}&text={s}')
    #api_response = requests.post(f'{API_URL}{BOT_TOKEN}/sendDocument?chat_id={chat_id}',files=document, data=data)
    #requests.get(f'{API_URL}{BOT_TOKEN}/sendMessage?chat_id={chat_id}&text={message}')
    #api_response_json = api_response.json()
    #print(api_response_json['result']['message_id'])
    #requests.get(f'{API_URL}{BOT_TOKEN}/editMessageCaption?chat_id={chat_id}?inline_message_id={message}', data=data1)
    #s=cnt[str(ip_address)]
    r=requests.post(f'{API_URL}{BOT_TOKEN}/sendDocument?chat_id={chat_id}', files=document, data=data)
    print(r)
    r=r.json()
    print(r)
    #reply_id[str(ip_address)]=r['result']['message_id']
    
for packet in capture.sniff_continuously():
    data={'caption':f"Suspucious packet detected\n"}
    ip_address="";
    print("Length:",len(packet))
    data["caption"]+=f"Length:{len(packet)}\n"
    try:
        ip=packet["ip"] 
        print("Source Address:",ip.src)
        ip_address=ip.src;
        print("Destination Address:",ip.dst) 
        print("IP Protocol:",ip.proto)
        data["caption"]+=f"Source Address:{ip.src}\n"
        data["caption"]+=f"Destination Address:{ip.dst}\n"
        data["caption"]+=f"IP Protocol:{ip.proto}\n"
    except: 
        try: 
            ipv6=packet["ipv6"] 
            print("Source Address:",ipv6.src) 
            ip_address=ipv6.src;
            print("Destination Address:",ipv6.dst) 
            print("IP Protocol:",ip.proto)
            data["caption"]+=f"Source Address:{ipv6.src}\n"
            data["caption"]+=f"Destination Address:{ipv6.dst}\n"
            data["caption"]+=f"IP Protocol:{ip.proto}\n"
        except: 
            print("No IP address detected") 
            data["caption"]+=f"No IP address detected\n"
     
    
    try: 
        proto=0
        if('proto' in packet):
            proto=packet['tcp']
        else:
            proto=packet['udp']
        print("Source Port:",proto.srcport) 
        print("Destination Port:",proto.dstport)
        data["caption"]+=f"Source Port:{proto.srcport}\n"
        data["caption"]+=f"Destination Port:{proto.srcport}\n"
    except: 
        print("No Source and destination ports detected")
        data["caption"]+=f"No Source and destination ports detected\n"
    try:
        cnt[ip_address]+=1;
    except:
        cnt[ip_address]=1;
    if(cnt[ip_address]>10 and time.time()-tm[ip_address]<0.1):
        try:
            requests.get(f'{API_URL}{BOT_TOKEN}/editMessageCaption?chat_id={chat_id}&message_id={reply_id[str(ip_address)]}&text={cnt[ip_address]}')
        except:
            wq(packet,ip_address)
    tm[ip_address]=time.time();