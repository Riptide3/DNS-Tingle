import struct
import socket

class MessageParser:
    def __init__(self, msg, localFile='dnsrelay.txt', foreignServer='10.3.9.4'):
        self.msg = msg
        self.queryMsg = {
            'header': self.parse_header(msg),
            'question': self.parse_question(msg)[0]
        }
        mapTable = self.get_map_table(localFile)
        self.resp = self.get_resp_msg(mapTable, foreignServer)
        self.respMsg = {
            'header': self.parse_header(self.resp),
            'question': self.parse_question(self.resp)[0],
            'answer': self.parse_answer(self.resp)
        }

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


    def get_formatted_cname(self, offset, recvMsg, rdlength):
        name = ''
        count = 1
        _offset = offset
        length = recvMsg[_offset]
        _rdlength = rdlength
        if length != 0xc0:
            _rdlength -= 1
        while count <= length and _rdlength > 0:
            if length == 0xc0:
                _, nameOffset = struct.unpack('>BB', recvMsg[_offset:_offset+2])
                if nameOffset == 0x0c:
                    _aname, _ = self.get_formatted_name(nameOffset, recvMsg)
                else:
                    _rdlength_ = struct.unpack('>H', recvMsg[nameOffset-2:nameOffset])
                    _aname = self.get_formatted_cname(nameOffset, recvMsg, _rdlength_)
                name += _name
                _offset += 2
                _rdlength -= 2
                if _rdlength <= 0:
                    break
                count = 1
                length = recvMsg[_offset]
                if length != 0xc0:
                    _rdlength -= 1
                    if _rdlength <= 0:
                        break
            else:
                name += chr(recvMsg[_offset+count])
                count += 1
                _rdlength -= 1
                if _rdlength <= 0:
                    break
                if count > length:
                    name += '.'
                    length = recvMsg[_offset+count]
                    if length != 0xc0:
                        _rdlength -= 1
                        if _rdlength <= 0:
                            break
                    _offset += count
                    count = 1
        return name


    def get_formatted_ip(self, offset, recvMsg):
        _ip = ()
        _ip = struct.unpack('>BBBB', recvMsg[offset:offset+4])
        ip = ''
        for part in _ip:
            ip += str(part)
            ip += '.'
        ip = ip.strip('.')
        return ip, offset+4


    def get_formatted_ipv6(self, offset, recvMsg):
        _ipv6 = ()
        _ipv6 = struct.unpack('>HHHHHHHH', recvMsg[offset:offset+16])
        ipv6 = ''
        for part in _ipv6:
            ipv6 += str(hex(part))[2:]
            ipv6 += ':'
        ipv6 = ipv6.strip(':')
        return ipv6, offset+16
    

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
            return question, offset+4


    def parse_answer(self, recvMsg):
        try:
            header = self.parse_header(recvMsg)
            ancount = header['ANCOUNT']
            _, offset = self.parse_question(recvMsg)
            aname = atype = aclass = ttl = rdlength = rddata = []
            print('解析完问题之后的偏移量 %d' % offset)
            while ancount > 0:
                print('答案个数%d' % ancount)
                _, nameOffset = struct.unpack('>BB', recvMsg[offset:offset+2])
                if nameOffset == 0x0c:
                    _aname, _ = self.get_formatted_name(nameOffset, recvMsg)
                else:
                    _rdlength_ = struct.unpack('>H', recvMsg[nameOffset-2:nameOffset])
                    _aname = self.get_formatted_cname(nameOffset, recvMsg, _rdlength_)
                offset += 2
                print('解析完域名之后的偏移量 %d' % offset)
                _atype, _aclass, _ttl, _rdlength = struct.unpack('>HHIH', recvMsg[offset:offset+10])
                offset += 10
                print('解析完资源长度之后的偏移量 %d' % offset)
                print('解析到的ATYPE为%d' % _atype)
                print('资源长度为%d' % _rdlength)
                if _atype == 1:
                    _rddata, offset = self.get_formatted_ip(offset, recvMsg)
                elif _atype == 5:
                    _rddata = self.get_formatted_cname(offset, recvMsg, _rdlength)
                    offset += _rdlength
                elif _atype == 28:
                    _rddata, offset = self.get_formatted_ipv6(offset, recvMsg)
                
                print('解析完资源之后的偏移量%d' % offset)

                aname.append(_aname)
                print(_aname)
                atype.append(_atype)
                print(_atype)
                aclass.append(_aclass)
                print(_aclass)
                ttl.append(_ttl)
                print(_ttl)
                rdlength.append(_rdlength)
                print(_rdlength)
                rddata.append(_rddata)
                print(_rddata)

                ancount -= 1

        except:
            print('答案解析出错') #FIXME:for debug
            aname = atype = aclass = ttl = rdlength = rddata =[]
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


    def get_resp_msg(self, mapTable, foreignServer):
        respMsg = self.local_query(mapTable)
        if self.respIp == '':
            respMsg = self.foreign_query(foreignServer)
        return respMsg
        

    def get_map_table(self, localFile):
        mapTable = {}
        with open(localFile, 'r') as f:
            for line in f:
                flag = line.find(' ')
                ip = line[:flag]
                domainName = line[(flag+1):(len(line)-1)].lower()
                mapTable[domainName] = ip
        return mapTable


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
            
        respMsg = struct.pack('>HHHHHH', self.queryMsg['header']['ID'], flags, 
                            self.queryMsg['header']['QDCOUNT'], ancount,
                            self.queryMsg['header']['NSCOUNT'], self.queryMsg['header']['ARCOUNT'])
        respMsg += bytes(self.msg[12:])
        if ancount > 0:
            respMsg += struct.pack('>HHHIH', 0xc00c, 1, 1, 3600, 4)  # TODO:貌似L不对
            ip = self.respIp.split('.')
            respMsg += struct.pack('BBBB', int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3])) #TODO:改一下试试
        return respMsg

    def foreign_query(self, foreignServer):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(self.msg, (foreignServer, 53))
        respMsg, srvAddr = sock.recvfrom(1024)
        sock.close()
        return respMsg