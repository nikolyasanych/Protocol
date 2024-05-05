import socket
import struct
import time
import pickle

class DNSServer:
    def __init__(self, cache_file=None):
        self.cache = {}
        self.cache_file = cache_file
        if cache_file is not None:
            try:
                with open(cache_file, 'rb') as file:
                    self.cache = pickle.load(file)
            except FileNotFoundError:
                pass

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 53))
        while True:
            data, addr = sock.recvfrom(512)
            response = self.handle_request(data)
            sock.sendto(response, addr)

    def handle_request(self, data):
        question = self.decode_question(data[12:])
        key = (question['name'], question['type'], question['class'])
        if key in self.cache and self.cache[key]['expires'] > time.time():
            print("FROM CACHE")
            response = self.build_response(data[:12],
                                           self.cache[key]['data'],
                                           key
                                           )
        else:
            response = self.forward_request(data)
            if response is None:
                return b''
            else:
                match key[1]:
                    case 1:
                        self.cache[key] = {'data': self.extract_data(response),
                                           'expires': self.get_ttl(response,
                                                                   key
                                                                   ),
                                           "ips": self.get_ips(response)}
                    case 12:
                        self.cache[key] = {'data': self.extract_data(response),
                                           'name': self.decode_question(
                                               response[56:], True
                                           ),
                                           'expires': self.get_ttl(response,
                                                                   key
                                                                   )}
                    case 2:
                        lst_info = response.split(b'ns')
                        ttl = struct.unpack('!L', lst_info[1][-6:-2])[0]
                        lst_names = []
                        main_name = self.decode_name(12, response)
                        for part in lst_info[1:]:
                            part_of_name = part[:1]
                            lst_names.append(
                                f"{(b'ns' + part_of_name).decode()}.{main_name}"
                            )
                        self.cache[key] = {'data': self.extract_data(response),
                                           'expires': time.time() + ttl,
                                           'names': lst_names}
                        lst_ips_for_names = self.get_ips(response)
                        lst_of_parts_for_type_a = [
                            b'\x00\x01\x00\x01\xc0\x0c' + part[1:] for part in
                            lst_info[-1].split(b'\xc0') if b'\x04' in part]
                        data_for_answer = []
                        for index, name in enumerate(lst_names):
                            first_part_of_name = name.split('.')[0].encode()
                            data_for_answer.append(
                                b'\x03' + first_part_of_name + b'\x06google\x03com\x00' +
                                lst_of_parts_for_type_a[
                                    index]
                            )
                        for index, name in enumerate(lst_names):
                            self.cache[(name, 1, 1)] = {
                                'data': [data_for_answer[index]],
                                'expires': time.time() + ttl,
                                'ips': [lst_ips_for_names[index]]
                            }

        if self.cache_file is not None:
            with open(self.cache_file, 'wb') as file:
                pickle.dump(self.cache, file)
        return response

    @staticmethod
    def forward_request(data):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(('ns1.google.com', 53))
            sock.send(data)
            response = sock.recv(512)
            return response

    @staticmethod
    def decode_question(data, link=False):
        name = []
        i = 0
        while 1:
            length = data[i]
            if not length:
                break
            name.append(data[i + 1:i + 1 + length].decode())
            i += length + 1
        if link:
            return '.'.join(name)
        q_type, q_class = struct.unpack('!HH', data[i + 1:i + 5])
        return {'name': '.'.join(name), 'type': q_type,
                'class': q_class}

    def decode_name(self, offset, data):
        name = []
        while True:
            length = struct.unpack('!B', data[offset:offset + 1])[0]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                offset = struct.unpack('!H', data[offset:offset + 2])[
                             0] & 0x3FFF
                name.append(self.decode_name(offset, data))
                break
            name.append(data[offset + 1:offset + 1 + length].decode())
            offset += length + 1
        return '.'.join(name)

    @staticmethod
    def extract_data(response):
        data = []
        i = 12
        while True:
            length = struct.unpack('!H', response[i + 10:i + 12])[0]
            data.append(response[i:i + 12 + length])
            i += 12 + length
            if i >= len(response):
                break
        return data

    def get_ttl(self, response, key):
        match key[1]:
            case 1:
                info = self.extract_data(response)[0]
                ttl = struct.unpack("!L", info[-6:-2])[0]
            case 12:
                ttl = struct.unpack("!L", response[51:55])[0]
        return time.time() + ttl

    @staticmethod
    def get_ips(response):
        lst_ips = []
        trying_get_ips = response.split(b"\x04")
        if response.count(b"\x04") == 5:
            trying_get_ips = trying_get_ips[1:]
        for part in trying_get_ips[1:]:
            tuple_ips = map(str, struct.unpack("!4B", part[:4]))
            lst_ips.append(".".join(tuple_ips))
        return lst_ips

    def build_response(self, query_header, data, key):
        match key[1]:
            case 1:
                trance_id = query_header[:2]
                flags = b'\x85\x00'
                count_ips = len(self.cache[key]['ips'])
                other_four_fields = struct.pack('!4H',
                                                1, count_ips, 0, 0
                                                )
                header = trance_id + flags + other_four_fields
            case 12:
                trance_id = query_header[:2]
                flags = b'\x85\x00'
                other_four_fields = struct.pack('!4H', 1, 1, 0, 0)
                header = trance_id + flags + other_four_fields
            case 2:
                trance_id = query_header[:2]
                flags = b'\x85\x00'
                count_names = len(self.cache[key]['names'])
                other_four_fields = struct.pack("!4H", 1, count_names,
                                                0,
                                                count_names * 2
                                                )
                header = trance_id + flags + other_four_fields
        full_info = b''
        for part in data:
            full_info += part
        return header + full_info


if __name__ == '__main__':
    server = DNSServer('dns_cache.pickle')
    server.run()
