import struct # 处理字节流
import socket # 与远端服务器通信
import time   # 获取时间戳
import fcntl  # 使用线程锁

class MessageParser:
    def __init__(self, msg, cacheFile='cache.txt', localFile='dnsrelay.txt', foreignServer='10.3.9.4'):
        self.msg = msg
        self.queryMsg = {
            'header': self.parse_header(msg),
            'question': self.parse_question(msg)
        }
        self.resp = self.get_resp_msg(cacheFile, localFile, foreignServer)
        self.respMsg = {
            'header': self.parse_header(self.resp),
            'question': self.parse_question(self.resp),
            'answer': self.parse_answer(self.resp)
        }

# header
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# 解析报头
    def parse_header(self, recvMsg):
        try:
            (Id, flags, qdcount, ancount, nscount, arcount) = struct.unpack('>HHHHHH', recvMsg[0:12])
            header = {
                'ID': Id,
                'QR': flags >> 15 & 0x0001,
                'OPCODE': flags >> 11 &0x000f,
                'AA': flags >> 10 & 0x0001,
                'TC': flags >> 9 & 0x0001,
                'RD': flags >> 8 & 0x0001,
                'RA': flags >> 7 &0x0001,
                'RCODE': flags & 0x000f,
                'QDCOUNT': qdcount,
                'ANCOUNT': ancount,
                'NSCOUNT': nscount,
                'ARCOUNT': arcount
            }
        except:
            header = {
                'ID': 0,
                'QR': 0,
                'OPCODE': 0,
                'AA': 0,
                'TC': 0,
                'RD': 0,
                'RA': 0,
                'RCODE': 0,
                'QDCOUNT': 0,
                'ANCOUNT': 0,
                'NSCOUNT': 0,
                'ARCOUNT': 0
            }
        finally:
            return header


# 解析报文中的域名
    def get_formatted_name(self, offset, recvMsg):
        name = ''
        count = 1
        _offset = offset
        length = recvMsg[_offset]
        while count <= length:
            name += chr(recvMsg[_offset+count])
            count += 1
            if count > length and recvMsg[_offset+count] != 0:
                name += '.'
                length = recvMsg[_offset+count]
                _offset += count
                count = 1
        _offset = _offset + count + 1
        return name, _offset


# 解析报文中的IP地址
    def get_formatted_ip(self, recvMsg):
        _ip = ()
        _ip = struct.unpack('>BBBB', recvMsg[-4:])
        ip = ''
        for part in _ip:
            ip += str(part)
            ip += '.'
        ip = ip.strip('.')
        return ip


# 解析报文中的IPV6地址
    def get_formatted_ipv6(self, recvMsg):
        _ipv6 = ()
        _ipv6 = struct.unpack('>HHHHHHHH', recvMsg[-16:])
        ipv6 = ''
        for part in _ipv6:
            ipv6 += str(hex(part))[2:]
            ipv6 += ':'
        ipv6 = ipv6.strip(':')
        return ipv6

# question
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                     QNAME                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QCLASS                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# 解析问题
    def parse_question(self, recvMsg):
        try:
            offset = 12
            qname, offset = self.get_formatted_name(offset, recvMsg)
            qtype, qclass = struct.unpack('>HH', recvMsg[offset:offset+4])
            question = {
                'QNAME': qname,
                'QTYPE': qtype,
                'QCLASS': qclass
            }
        except:
            question = {
                'QNAME': '',
                'QTYPE': 0,
                'QCLASS': 0
            }
        finally:
            return question

# resource record
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                                               /
# /                      NAME                     /
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     CLASS                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TTL                      |
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    RDLENGTH                   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
# /                     RDATA                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# 解析回答
    def parse_answer(self, recvMsg):
        try:
            header = self.parse_header(recvMsg)
            question = self.parse_question(recvMsg)
            aname = question['QNAME']
            qtype = question['QTYPE']
            if qtype == 1:
                atype, aclass, ttl, rdlength = struct.unpack('>HHIH', recvMsg[-14:-4])
                rddata = self.get_formatted_ip(recvMsg)
            elif qtype == 28:
                atype, aclass, ttl, rdlength = struct.unpack('>HHIH', recvMsg[-26:-16])
                rddata = self.get_formatted_ipv6(recvMsg)

        except:
            atype = aclass = ttl = rdlength = 0
            aname = rddata = ''
        finally:
            answer = {
                'ANAME': aname,
                'ATYPE': atype,
                'ACLASS': aclass,
                'TTL': ttl,
                'RDLENGTH': rdlength,
                'RDDATA': rddata
            }
            return answer


# 获取回复报文
    def get_resp_msg(self, cacheFile, localFile, foreignServer):
        cacheTable = self.get_cache_table(cacheFile)
        respMsg = self.cache_query(cacheTable)
        if self.respIp == '':
            mapTable = self.get_map_table(localFile)
            respMsg = self.local_query(mapTable)
            if self.respIp == '':
                respMsg = self.foreign_query(foreignServer)
                answer = self.parse_answer(respMsg)
                if answer['ATYPE'] == 1:
                    with open(cacheFile, 'a') as f:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        f.write(answer['RDDATA'] + ' ' + 
                                answer['ANAME'] + ' ' + 
                                str(answer['TTL']+time.time()) + '\n')
        return respMsg
        
# 获取cache映射表
    def get_cache_table(self, cacheFile):
        cacheTable = {}
        dName_IP_timeStamp = ''
        with open(cacheFile, 'a+') as r:
            fcntl.flock(r.fileno(), fcntl.LOCK_EX)
            lines = r.readlines()
        with open(cacheFile, 'w') as w:
            fcntl.flock(w.fileno(), fcntl.LOCK_EX)
            for line in lines:
                dName_IP_timeStamp = line.strip().split(' ')
                timeNow = time.time()
            if (len(dName_IP_timeStamp) == 3
                and dName_IP_timeStamp[0] != ''
                and dName_IP_timeStamp[1] != ''
                and dName_IP_timeStamp[2] != ''):
                if timeNow <= float(dName_IP_timeStamp[2]):
                    w.write(line)
        with open(cacheFile, 'r') as f:
            for line in f.readlines():
                dName_IP_timeStamp = line.strip().split(' ')
                if (len(dName_IP_timeStamp) == 3
                    and dName_IP_timeStamp[0] != ''
                    and dName_IP_timeStamp[1] != ''
                    and dName_IP_timeStamp[2] != ''):
                    cacheTable[dName_IP_timeStamp[1]] = dName_IP_timeStamp[0]
        return cacheTable

# 获取本地DNS映射表
    def get_map_table(self, localFile):
        mapTable = {}
        with open(localFile, 'r') as f:
            for line in f.readlines():
                domainName_IP = line.strip().split(' ')
                if domainName_IP[0] != '' and domainName_IP[1] != '':
                    mapTable[domainName_IP[1]] = domainName_IP[0]
        return mapTable

# 在cache中查找IP
    def cache_query(self, cacheTable):
        self.respIp = ''
        try:
            if self.queryMsg['question']['QTYPE'] == 1 and self.queryMsg['question']['QNAME'] in cacheTable:
                self.respIp = cacheTable[self.queryMsg['question']['QNAME']]
        except:
            self.respIp = ''

        if self.respIp == '0.0.0.0' or self.respIp == '':
            flags = 0x8183
            ancount = 0
        else:
            flags = 0x8180
            ancount = 1

        respMsg = self.construct_respMsg(flags, ancount)
        return respMsg

# 在本地文件中查找IP
    def local_query(self, mapTable):
        self.respIp = ''
        try:
            if self.queryMsg['question']['QTYPE'] == 1 and self.queryMsg['question']['QNAME'] in mapTable:
                self.respIp = mapTable[self.queryMsg['question']['QNAME']]
        except:
            self.respIp = ''
            
        if self.respIp == '0.0.0.0' or self.respIp == '':
            flags = 0x8183
            ancount = 0
        else:
            flags = 0x8180
            ancount = 1

        respMsg = self.construct_respMsg(flags, ancount)
        return respMsg

# 构造回复报文
    def construct_respMsg(self, flags, ancount):
        respMsg = struct.pack('>HHHHHH', self.queryMsg['header']['ID'], flags, 
                                self.queryMsg['header']['QDCOUNT'], ancount,
                                self.queryMsg['header']['NSCOUNT'], self.queryMsg['header']['ARCOUNT'])
        respMsg += bytes(self.msg[12:])
        if ancount > 0:
            respMsg += struct.pack('>HHHIH', 0xc00c, 1, 1, 3600, 4)
            ip = self.respIp.split('.')
            respMsg += struct.pack('>BBBB', int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3]))
        return respMsg


# 向远端服务器发送DNS请求
    def foreign_query(self, foreignServer):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(self.msg, (foreignServer, 53))
        respMsg, srvAddr = sock.recvfrom(1024)
        sock.close()
        return respMsg