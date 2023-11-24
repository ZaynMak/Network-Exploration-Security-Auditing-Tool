import time, sys, json, subprocess

results = {}
def main():
    file_in = sys.argv[1]
    file_out = sys.argv[2]

    
    read_file = open(file_in, "r")
    for line in read_file:
        line = line.strip()
        results[line]={'scan_ time': time.time()}
        ipv4s = scanner(line)
        # print("line: " + line + " ipv4s")
        ipv6s = scanner(line, 'AAAA')
        # print("line: " + line + " ipv6s")
        # ipv4s = ipv4_scanner(line)
        # ipv6s = ipv6_scanner(line)
        results[line]['ipv4'] = ipv4s
        results[line]['ipv6'] = ipv6s

        #call other scanners for each website

    
    with open (file_out, "w" ) as f:
        json.dump(results, f, sort_keys = True, indent=4)
        f.close()
    
    read_file.close()
    
def scanner(name, typ = 'A'):
    ipvs = []
    for resolver in open('public_dns_resolvers.txt', 'r'):
        resolver = resolver.strip()
        try:
            result = subprocess.check_output(["nslookup", "-type=" + typ, name, resolver], timeout = 2, stderr = subprocess.STDOUT).decode('utf-8')
        except subprocess.TimeoutExpired:
            continue
        # if typ == 'AAAA':
            # print("before result" + result)
        # find where non-authoritative answer is
        start = result.find("Non-authoritative answer:") + 25
        result = result[start:].strip()
        # if typ == 'AAAA':
        #     print("after result" + result)
        # find where the address is
        if typ == 'A':
            while result.find("Address:") != -1:
                start = result.find("Address:") + 8
                end = result.find("\n", start)
                temp = result[start:end]
                if temp not in ipvs:
                    ipvs.append(result[start:end])
                result = result[end:].strip()
        else:
            while result.find("address ") != -1:
                # print("result: " + result)
                start = result.find("address ") + 8
                end = result.find("\n", start)
                temp = result[start:end]
                if temp not in ipvs:
                    ipvs.append(result[start:end])
                result = result[end:].strip()

    return ipvs

def ipv4_scanner(name):
    ipv4s = []
    for resolver in open('public_dns_resolvers.txt', 'r'):
        resolver = resolver.strip()

        try:
            result = subprocess.check_output(["nslookup", name, resolver], timeout = 2, stderr = subprocess.STDOUT).decode('utf-8')
        except subprocess.TimeoutExpired:
            continue
        # print("before result" + result)
        # find where non-authoritative answer is
        start = result.find("Non-authoritative answer:") + 25
        result = result[start:].strip()
        # print("after result" + result)
        # find where the address is
        while result.find("Address:") != -1:
            start = result.find("Address:") + 8
            end = result.find("\n", start)
            temp = result[start:end]
            if temp not in ipv4s:
                ipv4s.append(result[start:end])
            result = result[end:].strip()
    
    return ipv4s

def ipv6_scanner(name):
    ipv6s = []
    for resolver in open('public_dns_resolvers.txt', 'r'):
        resolver = resolver.strip()

        try:
            result = subprocess.check_output(["nslookup", name, resolver, '-type=AAAA'], timeout = 2, stderr = subprocess.STDOUT).decode('utf-8')
        except subprocess.TimeoutExpired:
            continue
        # print(result)
        # print("before result" + result)
        # find where non-authoritative answer is
        start = result.find("Non-authoritative answer:") + 25
        result = result[start:].strip()
        # print("after result" + result)
        # find where the address is
        while result.find("Address:") != -1:
            start = result.find("Address:") + 8
            end = result.find("\n", start)
            temp = result[start:end]
            if temp not in ipv6s:
                ipv6s.append(result[start:end])
            result = result[end:].strip()
    
    return ipv6s


if __name__ == "__main__":
    main()

#subprocess.check_output(["nslookup", "northwestern.edu", "8.8.8.8"], timeout = 2, stderr = subprocess.STDOUT).decode("utf-8")
#'Server:\t\t8.8.8.8\nAddress:\t8.8.8.8#53\n\nNon-authoritative answer:\nName:\tnorthwestern.edu\nAddress: 129.105.136.48\n\n'