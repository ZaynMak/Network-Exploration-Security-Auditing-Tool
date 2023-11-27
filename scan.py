import time, sys, json, subprocess, http.client, socket
import maxminddb

results = {}

check =['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
def main():
    timer = time.time()

    file_in = sys.argv[1]
    file_out = sys.argv[2]

    
    read_file = open(file_in, "r")
    for line in read_file:
        print(line)
        line = line.strip()
        results[line]={'scan_time': time.time()}
        scanner(line)
        print('ipv4')
        scanner(line, 'AAAA')
        print('ipv6')
        http_scanner(line)
        print('http')
        #tls_versions(line)
        print('tls')
        rdns(line)
        print('rdns')
        rtt(line) 
        print('rtt')
        geos(line)
        print('geos')

        
        #call other scanners for each website

    
    with open (file_out, "w" ) as f:
        json.dump(results, f, sort_keys = True, indent=4)
        f.close()
    
    read_file.close()
    #print("Time: ", time.time() - timer)
    
def scanner(name, typ = 'A'):
    ipvs = []
    for resolver in open('public_dns_resolvers.txt', 'r'):
        resolver = resolver.strip()
        try:
            result = subprocess.check_output(["nslookup", "-type=" + typ, name, resolver], timeout = 2, stderr = subprocess.STDOUT).decode('utf-8')
        except subprocess.TimeoutExpired:
            continue

        # find where non-authoritative answer is
        start = result.find("Non-authoritative answer:") + 25
        result = result[start:].strip()

        # find where the address is
        while result.find("Address:") != -1:
            start = result.find("Address:") + 8
            end = result.find("\n", start)
            temp = result[start:end].strip()
            if temp not in ipvs:
                ipvs.append(temp)
                result = result[end:].strip()
            result = result[end:].strip()
            


        if typ == 'A': 
            results[name]['ipv4'] = ipvs
        else:
            results[name]['ipv6'] = ipvs

def http_helper(name, counter=0):
    if counter < 10:
        secure = False
        if "https" in name:
            secure = True
            name = name[8:]
        elif "http" in name:
            name = name[7:]

        slash = "/"
        loc_slash = name.find("/")
        if loc_slash != -1:
            slash = name[loc_slash:]
            name = name[:loc_slash]

        if secure:
            connect = http.client.HTTPSConnection(name, timeout=10)
        else:
            connect = http.client.HTTPConnection(name, timeout=10)

        try:
            connect.request("GET", slash, headers={"Host": name})
            response = connect.getresponse()

            if str(response.status)[0:2] == '30':
                msg = response.msg.as_string()
                loc = msg.find("ocation:")
                start = msg[loc + 9:]
                end = start.find('/\n')
                if end == -1:
                    end = start.find('\n')
                new_name = start[:end]
                return http_helper(new_name, counter+1)
            else:
                return response, secure
        except Exception as e:
            print("ERROR helper: ", e)
            return None, secure

    else:
        return None, False
    

def http_scanner(name):
    server = None
    insecure = True
    redirect = False
    hsts = False
    new_response = None

    connect = http.client.HTTPConnection(name, timeout=10)
    try:
        connect.request("GET", "/", headers={"Host": name})
        response = connect.getresponse()

        if str(response.status)[0:2] == '30':
            msg = response.msg.as_string()
            loc = msg.find("ocation:")
            start = msg[loc + 9:]
            end = start.find('/\n')
            if end == -1:
                end = start.find('\n')
            new_name = start[:end]

            new_response, redirect = http_helper(new_name)
        if new_response:
            response = new_response
        if response:
            for line in response.msg.as_string().splitlines():

                if "erver:" in line:
                    server = line[line.find('erver:') + 7 :].strip()
                    
                if "strict-transport-security:" in line.lower():
                    hsts = True

    except Exception as e:
        print("ERROR: ", e)
        print("Insecure", name)
        insecure = False

    results[name]['http_server'] = server
    results[name]['insecure_http'] = insecure
    results[name]['redirect_to_https'] = redirect
    results[name]['hsts'] = hsts


def tls_versions(name):
    tls =[]
    root_ca = None
    try:
        result = subprocess.check_output(['nmap', '--script', 'ssl-enum-ciphers', '-p', '443', name], timeout = 10, stderr = subprocess.STDOUT).decode('utf-8')
        for c in check:
            if c in result:
                tls.append(c)
    except subprocess.TimeoutExpired:
        pass
    results[name]['tls_versions'] = tls
    if tls:
        try:
            result = subprocess.check_output(['openssl', 's_client', '-connect', name + ":443"], input = b'', timeout= 10, stderr= subprocess.STDOUT).decode('utf-8')
            start = result.find("Certificate chain")
            end = result.find("Server certificate")
            result = result[start:end]
            lines = result.splitlines()
            root_ca_line = lines[-2]
            start = root_ca_line.find("O =") + 4
            if root_ca_line[start] == '\"':
                start += 1
                end = root_ca_line.find('\"', start)
            else:
                end = root_ca_line.find(',', start)
            root_ca = root_ca_line[start:end]

        except Exception as e:
            print("ERROR: ", e)
        
    results[name]['root_ca'] = root_ca

def rdns(name):
    rdns = []
    for ipv4 in results[name]['ipv4']:
        try:
            result = subprocess.check_output(['nslookup', ipv4], timeout = 10, stderr = subprocess.STDOUT).decode('utf-8')
            start = result.find("Non-authoritative answer:") + 25
            result = result[start:].strip()

            while result.find("name =") != -1:
                start = result.find("name =") + 7
                end = result.find("\n", start)
                temp = result[start:end]
                if temp not in rdns:
                    rdns.append(result[start:end])
                result = result[end:].strip()
        except:
            continue

    results[name]['rdns'] = rdns

    #response.status response.reason i.e 404 not found

def rtt(name):
    rtts = []
    for ipv4 in results[name]['ipv4']:
        time1 = time.time()
        try:
            connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect.settimeout(2)
            connect.connect((ipv4, 80))
            connect.close()
            time2 = time.time()
            rtts.append(time2 - time1)
        except Exception as e1:
            print("ERROR rtt port 80: ", ipv4, e1)
            time1 = time.time()
            try:
                connect2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                connect2.settimeout(2)
                connect2.connect((ipv4, 20))
                connect2.close()
                time2 = time.time()
                rtts.append(time2 - time1)
            except Exception as e2:
                print("ERROR rtt port 20: ", e2)
                time1 = time.time()
                try:
                    connect3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    connect3.settimeout(2)
                    connect3.connect((ipv4, 443))
                    connect3.close()
                    time2 = time.time()
                    rtts.append(time2 - time1)
                except Exception as e3:
                    print("ERROR rtt port 443: ", e3)
    
    if rtts:
        results[name]['rtt'] = [int(1000 * min(rtts)), int(1000 * max(rtts))]
    else:
        results[name]['rtt'] = None
    
def geos(name):
    geos=[]
    with maxminddb.open_database('GeoLite2-City.mmdb') as db:
        for ipv4 in results[name]['ipv4']:
            try:
                loc = db.get(ipv4)
            except:
                continue
            if "country" not in loc:
                continue
            country = loc['country']['names']['en']
            if country == "United States":
                if 'subdivisions' in loc:
                    state = loc['subdivisions'][0]['names']['en']
                    country = state + ", " + country
            if 'city' in loc:
                city = loc['city']['names']['en']
                country = city + ", " + country
            if country not in geos:
                geos.append(country)
    db.close()
    results[name]['geo_locations'] = geos

if __name__ == "__main__":
    main()

#subprocess.check_output(["nslookup", "northwestern.edu", "8.8.8.8"], timeout = 2, stderr = subprocess.STDOUT).decode("utf-8")
#'Server:\t\t8.8.8.8\nAddress:\t8.8.8.8#53\n\nNon-authoritative answer:\nName:\tnorthwestern.edu\nAddress: 129.105.136.48\n\n'