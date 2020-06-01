import socket
import glob
import json
import datetime
from msg_controller import MSGController


def load_records_info():
    json_info = {}
    info_files = glob.glob('infos/*.info')
    print('Загрузка кэша.')

    for zone in info_files:
        with open(zone) as file:
            data = json.load(file)
            origin = data['origin']
            json_info[origin] = data
    print(f'Загрузка из кэша завершена. Загружено {len(json_info)} объектов.')
    return json_info


def make_info_from_response(data, domain):
    question = build_question(domain, 'a')
    ANCOUNT = int.from_bytes(data[6:8], 'big')
    answer = data[12 + len(question):]
    records = get_records_from_answer(answer, ANCOUNT)
    origin = '.'.join(domain)
    time = str(datetime.datetime.now())
    cash_data = {'origin': origin, 'time': time, 'data': records, 'ttl': 360}
    INFO_DATA[origin] = cash_data
    save_info_data(cash_data)
    return cash_data


def save_info_data(data):
    with open(f'infos/{data["origin"]}.info', 'w+') as file:
        json.dump(data, file)


def make_ipv4_from_bytes(data):
    ip = ''
    for byte in data:
        ip += str(byte) + '.'
    return ip.rstrip('.')


def get_records_from_answer(answer, count):
    ptr = 0
    records = {}
    for _ in range(count):
        record = {}
        rec_type = int.from_bytes(answer[ptr + 2: ptr + 4], 'big')
        ttl = int.from_bytes(answer[ptr + 6:ptr + 10], 'big')
        rd_length = int.from_bytes(answer[ptr + 10: ptr + 12], 'big')
        rd_data = ''
        if rec_type == 1:
            rd_data = make_ipv4_from_bytes(answer[ptr + 12:ptr + 12 + rd_length])
        ptr += 12 + rd_length
        rec_type = MSGController.make_type_from_number(rec_type)
        record['ttl'] = ttl
        record['value'] = rd_data
        if rec_type in records:
            records[rec_type].append(record)
        else:
            records[rec_type] = [record]
    return records


def find_data(domain):
    request = build_request(domain)
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        temp_sock.sendto(request, GOOGLE_NS)
        data, _ = temp_sock.recvfrom(512)
    finally:
        temp_sock.close()
    info = make_info_from_response(data, domain)
    return info


def get_info(domain, info_data):
    info_name = '.'.join(domain)
    info = None
    if info_name in info_data:
        print(f'Данные по {info_name} найдены в кэше.')
        info = info_data[info_name]
        time = datetime.datetime.fromisoformat(info['time'])
        ttl = info['ttl']
        current_time = datetime.datetime.now()
        if (current_time - time).seconds > ttl:
            print(f'Данные по "{info_name}" устарели. Обращаюсь к старшему ДНС серверу.')
            info = find_data(domain)
    else:
        print(f'В кэше нет данных по "{info_name}". Обращаюсь к старшему ДНС серверу.')
        info = find_data(domain)

    return info


def get_records(data):
    domain, question_type = MSGController.get_question_domain(data)
    QT = ''
    if question_type == b'\x00\x01':
        QT = 'a'
    if question_type == (12).to_bytes(2, byteorder='big'):
        QT = 'ptr'

    recs = None
    if QT == 'a':
        info = get_info(domain, INFO_DATA)
        recs = info['data'][QT]

    return recs, QT, domain


def build_question(domain, rec_type):
    question = b''

    for part in domain:
        length = len(part)
        question += bytes([length])

        for char in part:
            question += ord(char).to_bytes(1, byteorder='big')

    if rec_type == 'a':
        question += (1).to_bytes(2, byteorder='big')

    question += (1).to_bytes(2, byteorder='big')  # класс интернет
    return question


def record_to_bytes(rec_type, ttl, value):
    record = b'\xc0\x0c'

    if rec_type == 'a':
        record += bytes([0]) + bytes([1])

    record += bytes([0]) + bytes([1])  # класс интернет
    record += int(ttl).to_bytes(4, byteorder='big')

    if rec_type =='a':
        record += bytes([0]) + bytes([4])

        for part in value.split('.'):
            record += bytes([int(part)])
            
    return record


def build_response_flags(flags):
    first_byte = flags[:1]
    second_byte = flags[1:2]
    QR = '1'
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(first_byte) & (1 << bit))

    AA = '1'
    TC = '0'
    RD = '1'
    RA = '1'
    Z = '000'
    RCODE = '0000'
    first_byte_str = QR + OPCODE + AA + TC + RD
    second_byte_str = RA + Z + RCODE

    return flags_to_bytes(first_byte_str) + flags_to_bytes(second_byte_str)


def flags_to_bytes(*args):
    string = ''
    for arg in args:
        string += arg
    return int(string, 2).to_bytes(1, byteorder='big')


def build_request(domain):
    ID = b'\xAA\xAA'
    FLAGS = b'\x01\x00'
    QDCOUNT = b'\x00\x01'
    ANCOUNT = (0).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARSCOUNT = (0).to_bytes(2, byteorder='big')
    header = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARSCOUNT
    question = build_question(domain, 'a')
    return header + question


def build_a_response(data):
    ID = data[0:2]
    FLAGS = build_response_flags(data[2:4])
    QDCOUNT = b'\x00\x01'
    records_data = get_records(data[12:])
    ANCOUNT = len(records_data[0]).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARSCOUNT = (0).to_bytes(2, byteorder='big')
    header = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARSCOUNT
    body = b''
    records, rec_type, domain = records_data
    question = build_question(domain, rec_type)
    for record in records:
        body += record_to_bytes(rec_type, record['ttl'], record['value'])
    print(f'Ответ на запрос типа "A" по "{".".join(domain)}" отправлен.')
    return header + question + body


def build_response(data):
    request_info = MSGController.parse_incoming_request(data)
    resp = b''
    if request_info['question']['QTYPE'] == 'a':
        print('Получен запрос типа "A". Разрешаю запрос...')
        resp = build_a_response(data)

    return resp


INFO_DATA = load_records_info()
GOOGLE_NS = '8.8.8.8', 53

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

print('Запуск...')
while True:
    data, addr = sock.recvfrom(512)
    response = build_response(data)
    sock.sendto(response, addr)

