from enum import IntEnum
from random import randint
import socket
import struct
import sys
import getopt


class QueryType(IntEnum):
    """
    The supported query types
    """
    A = 1
    NS = 2
    CNAME = 5
    # SOA = 6 # Unsupported
    MX = 15
    AAAA = 28
    # OPT = 41 # Unsupported


class RecordData:
    """
    The RData section
    """

    def __init__(self):
        """
        Construct an empty RecordData class. Use parse() to parse the data.
        """
        self.__dict__ = {
            field: None for field in ('_type', 'IP', 'NS', 'CName', 'Preference', 'ME')
        }

    def parse(self, type: QueryType, data: bytes, length: int, offset: int = 0):
        """
        Parse the RData

        :param type: The type of the answer
        :param data: The body of the DNS response
        :param length: The RDLength attribute; the length of RData
        :param offset: The starting point of RData
        :return: The starting point of the next field
        """
        self._type = type
        i = offset
        if self._type == QueryType.A:
            self.IP = data[i:i+length]
            i += length
        elif self._type == QueryType.NS:
            domain = DomainName()
            i = domain.parse(data, i)
            self.NS = domain
        elif self._type == QueryType.CNAME:
            domain = DomainName()
            i = domain.parse(data, i)
            self.CName = domain
        elif self._type == QueryType.MX:
            self.Preference = struct.unpack('H', data[i:i+2])[0]
            i += 2
            domain = DomainName()
            i = domain.parse(data, i)
            self.ME = domain
        elif self._type == QueryType.AAAA:
            self.IP = data[i:i+length]
            i += length
        else:
            pass
        return i

    def __str__(self):
        if self._type == QueryType.A:
            return ".".join(
                (str(x) for x in struct.unpack_from('!4B', self.IP)))
        elif self._type == QueryType.NS:
            return str(self.NS)
        elif self._type == QueryType.CNAME:
            return str(self.CName)
        elif self._type == QueryType.MX:
            return "Preference: {}, ME: {}".format(
                self.Preference, self.ME)
        elif self._type == QueryType.AAAA:
            ip = [hex(x)[2:] for x in struct.unpack_from('!8H', self.IP)]
            encounter = False
            i = 0
            while i < len(ip):
                if ip[i] == '0' and not encounter:
                    encounter = True
                    ip[i] = ''
                elif ip[i] == '0' and encounter:
                    ip.pop(i)
                    i -= 1
                elif ip[i] != '0' and encounter:
                    encounter = False
                    break
                i += 1
            return ':'.join(ip)
        else:
            pass

    def __repr__(self):
        return str(self)


class DomainName:
    """
    Handles domain names
    """

    def __init__(self, name: str = ''):
        self.__dict__ = {
            field: None for field in ('_domain', '_meta', '_split')
        }
        self._domain = name
        self._split = name.split('.')
        self._meta = [len(arr) for arr in self._split]

    def parse(self, data: bytes, offset: int = 0):
        """
        Parse domain names (pascal strings)

        :param data: The DNS response
        :param offset: The starting point of the domain name
        :return: The starting point of the next field
        """
        i = offset
        omit = False
        while i < len(data) and data[i] != 0:
            if data[i] == 0xc0:
                domain = DomainName()
                domain.parse(data, data[i + 1])
                self._domain += str(domain)
                i += 2
                omit = True
                break
            else:
                slicelen = data[i]
                i += 1
                self._domain = self._domain + \
                    data[i: i + slicelen].decode('ascii') + '.'
                i += slicelen
        if self._domain[-1] == '.':
            self._domain = self._domain[:-1]
        self._split = self._domain.split('.')
        self._meta = [len(arr) for arr in self._split]
        return i if omit else i + 1

    def __str__(self):
        return self._domain

    def __bytes__(self):
        str = b""
        for i in range(0, len(self._meta)):
            str += bytes([self._meta[i]]) + \
                bytes(self._split[i], 'ascii')
        str += b"\x00"
        return str

    def __repr__(self):
        return str(self)


class Query:
    """
    Construct and parse query messages
    """

    def __init__(self):
        self.__dict__ = {
            field: None
            for field in ("Name", "Type", "Class", "_meta")
        }

    def construct(self, name: str, type: QueryType):
        """
        Construct a Query object to later use __bytes__ to convert into network data

        :param name: The domain name to be queried
        :param type: The desired type of the DNS query
        """
        self.Name = DomainName(name)
        self.Type = type
        self.Class = 0x0001
        self._meta = [len(arr) for arr in name.split('.')]

    def parse(self, data: bytes, offset: int = 0):
        """
        Parse the DNS server echo of the query

        :param data: The DNS response
        :param offset: The starting point of the query message
        :return: The starting point of the next field
        """
        i = offset
        self.Name = DomainName()
        i = self.Name.parse(data, i)
        self.Type = QueryType.from_bytes(data[i: i + 2], 'big')
        self.Class = int.from_bytes(data[i + 2: i + 4], 'big')
        i += 4
        return i

    def __bytes__(self):
        str = bytes(self.Name)
        str += int(self.Type).to_bytes(2, 'big') + \
            int(self.Class).to_bytes(2, 'big')
        return str

    def __str__(self):
        return '\n\tQuery:\n\t\tName = {}\n\t\tType = {}\n\t\tClass = {}\n'.format(self.Name, str(self.Type)[10:], self.Class)

    def __repr__(self):
        return str(self)


class Answer:
    """
    Handle the RRs
    """

    def __init__(self):
        self.__dict__ = {
            field: None for field in
            ('Name', 'Type', 'Class', 'TTL', 'RDLength', 'RData')
        }

    def parse(self, data: bytes, offset: int = 0):
        """
        Parse the RRs

        :param data: The DNS response
        :param offset: The starting point the RR
        :return: The starting point of the next field
        """
        i = offset
        self.Name = DomainName()
        i = self.Name.parse(data, i)
        type, self.Class, self.TTL, self.RDLength = struct.unpack_from(
            "!2H1I1H", data, i)
        self.Type = QueryType(type)
        i += 10
        self.RData = RecordData()
        i = self.RData.parse(self.Type, data, self.RDLength, i)
        return i

    def __str__(self):
        return '\n\tAnswer:\n\t\tName = {}\n\t\tType = {}\n\t\tClass = {}\n\t\tTTL = {}\n\t\tRDLength = {}\n\t\tRData = {}\n'.format(
            self.Name, str(self.Type)[
                10:], hex(self.Class), self.TTL, self.RDLength, self.RData
        )

    def __repr__(self):
        return str(self)


class DNSResMsg:
    """
    Handle the DNS response
    """

    def __init__(self):
        self.__dict__ = {
            field: None
            for field in ('ID', 'QR', 'OpCode', 'AA', 'TC', 'RD', 'RA', 'Z',
                          'RCode', 'QDCount', 'ANCount', 'NSCount', 'ARCount',
                          'Queries', 'Answers', "NS", 'Additionals')}
        self.Queries = []
        self.Answers = []
        self.NS = []
        self.Additionals = []

    def parse(self, data: bytes):
        """
        Parse the DNS response

        :param data: The DNS response
        :return: None
        """
        self.ID, misc, self.QDCount, self.ANCount, self.NSCount, self.ARCount = struct.unpack_from(
            '!6H', data)
        self.QR = (misc & 0x8000) != 0
        self.OpCode = (misc & 0x7800) >> 11
        self.AA = (misc & 0x0400) != 0
        self.TC = (misc & 0x200) != 0
        self.RD = (misc & 0x100) != 0
        self.RA = (misc & 0x80) != 0
        self.Z = (misc & 0x70) >> 4  # Never used
        self.RCode = misc & 0xF
        i = 12
        for _ in range(self.QDCount):
            query = Query()
            i = query.parse(data, i)
            self.Queries.append(query)
        for _ in range(self.ANCount):
            answer = Answer()
            i = answer.parse(data, i)
            self.Answers.append(answer)
        for _ in range(self.NSCount):
            nameserver = Answer()
            i = nameserver.parse(data, i)
            self.NS.append(nameserver)
        for _ in range(self.ARCount):
            additional = Answer()
            i = additional.parse(data, i)
            self.Additionals.append(additional)

    def __str__(self):
        return 'DNSResMsg:\n\tID = {}\n\tQR = {}\n\tOpcode = {}\n\tAuthoritative = {}\n\tTruncated = {}\n\tRecursion Desired = {}\n\tRecursion Available = {}\n\tZ = {}\n\tRCode = {}\n\tQueries = {}\n\tAnswers = {}\n\tNameservers = {}\n\tAdditional RRs = {}\n'.format(
            self.ID, self.QR, self.OpCode, self.AA, self.TC, self.RD, self.RA, self.Z, self.RCode, self.Queries, self.Answers, self.NS, self.Additionals
        )


class DNSQryHeader:
    """
    DNS query header
    """
    Struct = struct.Struct('!6H')

    def __init__(self):
        self.__dict__ = {
            field: None
            for field in ('ID', 'QR', 'OpCode', 'TC', 'RD', 'Z',
                          'AD', 'NA', 'QDCount', 'ANCount', 'NSCount', 'ARCount')}

    def construct(self, id: int, rd: int, qdcount=1):
        """
        Construct query header

        :param id: The transaction ID
        :param rd: Recursion desired
        :param qdcount: The number of queries in one message
        :return: None
        """
        self.ID = id
        self.QR = 0
        self.OpCode = 0
        self.TC = 0
        self.RD = rd
        self.Z = 1
        self.AD = 0
        self.NA = 0
        self.QDCount = qdcount
        self.ANcount = 0
        self.NScount = 0
        self.ARcount = 0

    def __bytes__(self):
        def b(i): return int(i).to_bytes(2, 'big')
        str = b(self.ID)
        misc = self.QR << 4 | self.OpCode
        misc = misc << 2 | self.TC
        misc = misc << 1 | self.RD
        misc = misc << 2 | self.Z
        misc = misc << 1 | self.AD
        misc = misc << 1 | self.NA
        misc <<= 4
        str += b(misc)
        str += b(self.QDCount)
        str += b(self.ANcount)
        str += b(self.NScount)
        str += b(self.ARcount)
        return str


def query(dnsAddr: str, targetAddr: str, type: QueryType, recursive: int = 1):
    """
    Initiate a query

    :param dnsAddr: The address of the DNS server
    :param targetAddr: The domain name to be queried
    :param type: The type of the query
    :param recursive: 1 for recursive, 0 for iterative
    :return: The DNS response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dnsPort = 53
    transactionId = randint(1, 65534)
    questions = 1
    header = DNSQryHeader()
    header.construct(transactionId, recursive, questions)
    query = Query()
    query.construct(targetAddr, type)
    msg = bytes(header) + bytes(query)
    sock.sendto(msg, (dnsAddr, dnsPort))
    response, _ = sock.recvfrom(2048)
    sock.close()
    return response


if __name__ == "__main__":
    argv = sys.argv[1:]

    domain = "www.sina.com.cn"
    type = QueryType['A']
    dns = "114.114.114.114"
    recursive = True

    try:
        opts, args = getopt.getopt(
            argv, "d:t:D:i", ["type=", "dns=", "iterative"])
    except getopt.GetoptError:
        print(
            'dnsclient.py [--type <type>] [--dns <dns>] [--iterative] domain')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '--dns':
            dns = arg
        elif opt == '--iterative':
            recursive = False
        elif opt == '--type':
            type = QueryType[arg]
        else:
            print("invalid command: ", opt)
            print(
                'dnsclient.py --domain <domain> [--type <type>] [--dns <dns>] [--iterative]')
            sys.exit(2)
    domain = args[0]
    if recursive:
        q = query(dns, domain, type)
        res = DNSResMsg()
        res.parse(q)
        print(res)
    else:
        res = DNSResMsg()
        res.parse(query(dns, 'a.root-servers.net', QueryType.A))
        print(res)

        dns = str(res.Answers[0].RData)
        print("---------Next Iteration--------")

        res = DNSResMsg()
        res.parse(query(dns, domain, type))
        print(res)

        ended = res.Answers and str(
            res.Answers[0].Name) == domain

        while not ended:
            print("---------Next Iteration--------")
            if res.Answers and res.Answers[0].Type == QueryType.CNAME:
                ans = res.Answers[0]
                domain = str(ans.RData)
                res = DNSResMsg()
                res.parse(query(dns, domain, type))
                print(res)
            else:
                dns = str(res.NS[0].RData)
                res = DNSResMsg()
                res.parse(query(dns, domain, type))
                print(res)
            ended = res.Answers and (type == QueryType.CNAME or res.Answers[0].Type != QueryType.CNAME) and str(
                res.Answers[0].Name) == domain
