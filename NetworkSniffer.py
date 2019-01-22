import socket
import sys
import struct
import re

def receiveData(s):
    data=''
    try:
        data=s.recvfrom(65565)
    except:
        print("Pranimi i te dhenave nuk eshte bere me sukses!")
        sys.exc_info()
    return data[0]

#get TIME OF SERVICE  - eshte 8 bit i gjate
def getTOS(data):
    presedence={0:"Routine", 1:"Priority", 2:"Immediate", 3:"Flash", 4:"Flash Override", 5:"Critic?ECP", 6:"Internetwork Control", 7:"Network Control"}
    delay = {0:"Normal Delay", 1:"Low Delay"}
    throughput={0:"Normal throughput",1:"High throughput"}
    realiability={0:"Normal Realiability",1:"High Realiability"}
    cost={0:"High monetary cost",1:"Minimize monetary cost"}

    #krijimi i nje variable qe mbane bitin per delay, te cilin do ta emrojme me D
    D = data & 0x10 #0x10(ne heksadecimal) ne binar shendrrohet ne 00010000
    #qe mos ti marrim parasysh 4 bitat e fundit, i bejme shift
    D >>= 4
    #Variabla qe ruan bitin per throughput, do ta emrojme me T
    T = data & 0x8
    T>>=3
    R= data & 0x4
    R>>=2
    #variabla qe ruan bitin per cost po e shenojme me M
    M=data& 0x2
    M>>=1
    tabs="\n\t\t\t"
    #qe ta formojme te gjithe TOS duhet ti bejme concat te dhenat me larte
    TOS=presedence[data>>5]+tabs+delay[D]+tabs+throughput[T]+tabs+realiability[R]+tabs+cost[M]
    return TOS

def getFlags(data):
    flagR={0:"Reserved bit"}
    flagDF={0:"Fragment if necessary",1:"Do not fragment"}
    flagMF={0:"Last Fragment",1:"More fragments"}

    R=data & 0x8000
    R>>=15
    DF=data & 0x4000
    DF>>=14
    MF=data & 0x2000
    MF>>=13

    tabs="\t\n\n\n"
    flags=flagR[R]+tabs+flagDF[DF]+tabs+flagMF[MF]
    return flags

def getProtocol(protocolNr):
    protocolFile=open('Protocol.txt','r')  #Fajlli Protocol.txt qe permbane nr dhe te dhenat per te gjitha protokolet duhet te ruhet ne pathin qe eshte i vendosur fajlli Prove.py
    protocolData=protocolFile.read()
    
    #Per perdorimin e regular expressions duhet te behet import libraria "re"
    protocol=re.findall(r'\n'+str(protocolNr)+' (?:.)+\n',protocolData)
    if protocol:
        protocol=protocol[0]
        protocol=protocol.replace('\n','')
        protocol=protocol.replace(str(protocolNr),'')
        protocol=protocol.lstrip()
        return protocol
    else:
        return "Asnje protokol nuk eshte gjetur!"
         

HOST=socket.gethostbyname_ex(socket.gethostname())
HOST=HOST[2][1]

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

s.bind((HOST, 0))

# Perfshirja e IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#Kapja e te gjitha paketave
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
i=1
while True:
    i=i+1
    if(i==30):
        hyrja=input("Jane zene 30 paketat e para, deshironi te vazhdoni?\n----->")
        if(hyrja=="PO" or hyrja=="po" or hyrja=="Po" or hyrja=="pO"):
            continue
        else:
            break


    data= receiveData(s)

    #Pas pranimit duhet te ti bejme UNPACK te dhenat ne hyrje, qe kjo te realizohet duhet te behet import librarine struct
    unpackedData=struct.unpack('BBHHHBBH4s4s', data[:20])
    version_IHL=unpackedData[0]
    version=version_IHL >> 4 #shift te dhenat per 4 ne te djathte, qe do te thote 4 bitat e par e paraqesin versionin ndersa 4 te tjeret do jene 0
    #IHL do te thot INTERNET HEADER LENGTH 
    IHL=version_IHL & 0xF

    TOS=unpackedData[1]
    totalLength=unpackedData[2]
    ID=unpackedData[3] #ID variabla qe paraqet te dhenat per Identification

    flags=unpackedData[4]
    fragmentOffset=unpackedData[4]&0x1FFF

    TTL=unpackedData[5]

    protocolNr=unpackedData[6]
    headerChecksum=unpackedData[7] 

    sourceAddr=socket.inet_ntoa(unpackedData[8])
    destionationAddr=socket.inet_ntoa(unpackedData[9])

    print( "Madhesia e IP Packet te zene eshte: " + str(totalLength))
    print ("Raw data: "+str(data))
    print("Parsed data: ")
    print("version:\t\t"+str(version))
    print("HeaderLength:\t\t"+str(IHL*4)+"bytes")
    print ("Type of Service:\t"+str(getTOS(TOS)))
    print("Length:\t\t\t"+str(totalLength))
    print("ID:\t\t\t"+str(hex(ID))+"("+str(ID)+")")
    print("Flags:\t\t\t"+str(getFlags(flags)))
    print("Fragment Offset:\t"+str(fragmentOffset))
    print("TTL:\t\t\t"+str(TTL))
    print("Protocol:\t\t"+str(getProtocol(protocolNr)))
    print("Checksum:\t\t"+str(headerChecksum))
    print("Source Address:" +str( sourceAddr))
    print("Destionation: "+ str(destionationAddr))
    print("Payload:\n"+str(data[20:]))
    print("----------------------------------------------------------------------------------------------------------------------------")



