import subprocess
import itertools
import requests
import re
import json
import argparse
import sys

_old_excepthook = sys.excepthook


def myexcepthook(exctype, value, traceback):
    if exctype == KeyboardInterrupt:
        print("program was interrupted with Ctrl+C.\n")
    else:
        _old_excepthook(exctype, value, traceback)


def first_digit(line):
    mo = re.match(r'\s*[0-9]', line)
    return mo


def get_last_part(line):
    parts = line.split()
    return parts[len(parts)-1]


def filter_list(out):
    without_stars = itertools.takewhile(lambda x: "*" not in x, out)
    only_useful = filter(first_digit, without_stars)
    ip_list = list(map(get_last_part, only_useful))
    return ip_list


def get_ip_list(user_input, hop_count, timeout):
    res = subprocess.run(["tracert", "-d", "-h", str(hop_count), "-w", str(timeout), user_input], capture_output=True)
    if res.stderr != b'':
        print('error while working with tracert')
        print(res.stderr)
    out = str(res.stdout, encoding="cp866").split("\r\n")
    if len(out) == 2:
        print('tracert message')
        print(out[0])
    else:
        return filter_list(out)


def get_asn(ip):
    asn_query = r"https://stat.ripe.net/data/network-info/data.json?resource="
    asn_resp = requests.get(asn_query + ip)
    json_dict = json.loads(asn_resp.text)
    asn_arr = json_dict["data"]
    if len(asn_arr) != 0 and len(asn_arr["asns"]):
        asn = asn_arr["asns"][0]
        return asn


def get_country_provider(ip, is_grey):
    country_provider_query = "https://stat.ripe.net/data/address-space-hierarchy/data.json?resource="
    country_provider_resp = requests.get(country_provider_query + ip)
    json_dict = json.loads(country_provider_resp.text)
    cp_arr = json_dict["data"]["exact"]
    country = cp_arr[0]["country"]
    if is_grey:
        provider = "grey address is not managed by the RIPE NCC"
    elif len(cp_arr) != 0 and "descr" in cp_arr[0]:
        provider = cp_arr[0]["descr"]
    else:
        provider = "no provider info"
    return country, provider


def main(user_input, hops, timeout):
    ip_list = get_ip_list(user_input, hops, timeout)
    if ip_list:
        i = 0
        heading = '{:3}{:16}{:8}{:8}{}'\
            .format("№", "IP", "ASN", "country", "provider")
        print(heading)
        for ip in ip_list:
            i += 1
            asn = get_asn(ip)
            is_grey = not asn
            (country, provider) = get_country_provider(ip, is_grey)
            format_str = '{:3}{:16}{:8}{:8}{}'\
                .format(str(i), str(ip),str(asn), str(country), str(provider))
            print(format_str)


if __name__ == '__main__':
    sys.excepthook = myexcepthook
    parser = argparse.ArgumentParser()
    parser.add_argument('--hops', nargs=1, type=int,
                        help="maximum number of hops")
    parser.add_argument('-w', '--timeout', nargs=1,  type=int, action='store',
                        help="timeout for request to router")
    parser.add_argument('-d', '--destination', nargs=1, type=str, required=True, action="store",
                        help="ip or domain name to trace to")
    parsed = parser.parse_args()
    hops = 30
    timeout = 5000
    if parsed.hops:
        hops = parsed.hops[0]
    if parsed.timeout:
        timeout = parsed.timeout[0]
    main(parsed.destination[0], hops, timeout)