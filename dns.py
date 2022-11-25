import socket, glob, json

port = 53

ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #shows the socket uses IPV4 and UDP
sock.bind((ip, port))

def load_zone():

    jsonZone = {}
    zoneFiles = glob.glob('zones/*.zone')
    
    for zone in zoneFiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonZone[zonename] = data
    return jsonZone




zonedata = load_zone()

def get_domain_question(data):
    state = 0
    expectedlength = 0
    domainStr = ''
    domainParts = []
    x = 0
    totalLength = 0

    for byte in data:
        if state == 1:
            domainStr += chr(byte)
            x+=1            
            if x == expectedlength:
                domainParts.append(domainStr)
                domainStr = ''
                state=0
                x=0    
        else:
            if byte == 0:
                break
            state=1
            expectedlength=byte
        totalLength +=1

    questionType = data[totalLength+1:totalLength+3]

    return (domainParts, questionType)

def get_zone(domain):
    global zonedata

    zone_name = '.'.join(domain) + '.'
    return zonedata[zone_name]

def get_recs(data):
    domain, question = get_domain_question(data)
    qt = ''
    if question == b'\x00\x01':
        qt='a'

    zone = get_zone(domain)

    return (zone[qt], qt, domain)


def get_flags(flags):
    rFlags = ''
    QR = '1' #response will always have 1
    byte1 = bytes(flags[0:1])
    byte2 = bytes(flags[1:2])

    OPCode = ''
    for bit in range(1,5):
        OPCode += str(ord(byte1)&(1<<bit))

    AA = '1'

    TC = '0'

    RD = '0'

    RA = '0'

    Z = '000'

    RCODE = '0000' #Room for improvement

    return int(QR+OPCode+AA+TC+RD,2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE).to_bytes(1, byteorder='big')

def build_question(domainname, rectype):
    qbytes = b''
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])
    
        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    qbytes += (0).to_bytes(1, byteorder='big')

    #Query Type
    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')
    
    #Query Class (1 for internet)
    qbytes += (1).to_bytes(2, byteorder='big')

    return(qbytes)

def rec_to_bytes(domainName, recType, recTTL, recVal):

    #Domain name offset
    rBytes = b'\xc0\x0c'

    if recType == 'a':
        rBytes += (1).to_bytes(2, byteorder='big')

    #Query Class (1 for internet)
    rBytes += (1).to_bytes(2, byteorder='big')

    rBytes += int(recTTL).to_bytes(4, byteorder='big')

    #Length of Record information (4 bytes for IPV4)
    if recType == 'a':
        rBytes += (4).to_bytes(2, byteorder='big')

        for part in recVal.split('.'):
            rBytes += bytes([int(part)])

    return rBytes

    


def build_response(data):

    #Get Transaction ID
    transactionID = data[0:2] 
    TID = ''
    for byte in transactionID:
        TID += hex(byte)[2:]

    #Get Flags
    flags = get_flags(data[2:4])

    #Question Count
    QDCOUNT = b'\x00\x01'

    #Answer Count
    ANSWERS = len(get_recs(data[12:])[0]).to_bytes(2, byteorder='big')

    #Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    #Additional Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = transactionID+flags+QDCOUNT+ANSWERS+NSCOUNT+ARCOUNT

    #Get answer for Query
    records, rectype, domainname = get_recs(data[12:])

    #Question portion of the DNS Response
    dnsquestion = build_question(domainname, rectype)

    dnsbody = b''

    #Builds the DNS Response Body with all of the individual records
    for record in records:
        dnsbody += rec_to_bytes(domainname, rectype, record["ttl"], record["value"])

    #Returns full DNS Response to the requester
    return dnsheader + dnsquestion + dnsbody


while 1:
    data, addr = sock.recvfrom(512)
    r = build_response(data)
    sock.sendto(r, addr)