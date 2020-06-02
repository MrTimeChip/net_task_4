class MSGController:

    @staticmethod
    def parse_incoming_request(data):
        header = MSGController.parse_header(data)
        domain_parts, question_type = MSGController.get_question_domain(data[12:])
        domain = '.'.join(domain_parts)
        type_number = int.from_bytes(question_type, 'big')
        parsed_type = MSGController.make_type_from_number(type_number)
        question = {'QNAME': domain, 'QTYPE': parsed_type,
                    'QCLASS': 'internet'}
        return {'header': header, 'question': question}

    @staticmethod
    def parse_header(data):
        ID = data[0:2]
        FLAGS = MSGController.parse_flags(data[2:4])
        QDCOUNT = int.from_bytes(data[4:6], 'big')
        ANCOUNT = int.from_bytes(data[6:8], 'big')
        NSCOUNT = int.from_bytes(data[8:10], 'big')
        ARCOUNT = int.from_bytes(data[10:12], 'big')
        header = {'ID': ID,
                  'FLAGS': FLAGS,
                  'QDCOUNT': QDCOUNT,
                  'ANCOUNT': ANCOUNT,
                  'NSCOUNT': NSCOUNT,
                  'ARCOUNT': ARCOUNT}
        return header

    @staticmethod
    def parse_flags(flags):
        first_byte = flags[:1]
        second_byte = flags[1:2]
        QR = MSGController.get_bit_in_byte(first_byte, 0)
        OPCODE = ''
        for bit in range(1, 5):
            OPCODE += MSGController.get_bit_in_byte(first_byte, bit)
        AA = MSGController.get_bit_in_byte(first_byte, 5)
        TC = MSGController.get_bit_in_byte(first_byte, 6)
        RD = MSGController.get_bit_in_byte(first_byte, 7)
        RA = MSGController.get_bit_in_byte(second_byte, 8)
        Z = '0000'
        RCODE = ''
        for bit in range(4, 8):
            RCODE += MSGController.get_bit_in_byte(first_byte, bit)
        flags_data = {'QR': QR,
                      'OPCODE': OPCODE,
                      'AA': AA,
                      'TC': TC,
                      'RD': RD,
                      'RA': RA,
                      'Z': Z,
                      'RCODE': RCODE}
        return flags_data

    @staticmethod
    def get_question_domain(data):
        state = 0
        expected_length = 0
        domain_string = ''
        domain_parts = []
        x = 0
        y = 0
        for byte in data:
            if state == 1:
                if byte != 0:
                    domain_string += chr(byte)
                x += 1
                if x == expected_length:
                    domain_parts.append(domain_string)
                    domain_string = ''
                    state = 0
                    x = 0
                if byte == 0:
                    domain_parts.append(domain_string)
                    break
            else:
                state = 1
                expected_length = byte
            y += 1

        question_type = data[y: y + 2]
        return domain_parts, question_type

    @staticmethod
    def get_bit_in_byte(byte, position):
        return str(ord(byte) & (1 << position))

    @staticmethod
    def make_type_from_number(type):
        if type == 1:
            return 'a'
        if type == 2:
            return 'ns'
