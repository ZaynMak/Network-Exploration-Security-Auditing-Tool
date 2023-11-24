import time, sys, json, subprocess, http.client

results = {}
def main():
    file_in = sys.argv[1]
    file_out = sys.argv[2]

    
    read_file = open(file_in, "r")
    for line in read_file:
        line = line.strip()
        results[line]={'scan_ time': time.time()}
        # scanner(line)
        # scanner(line, 'AAAA')
        http_scanner(line)
        
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

        # find where non-authoritative answer is
        start = result.find("Non-authoritative answer:") + 25
        result = result[start:].strip()

        # find where the address is
        if typ == 'A':
            while result.find("Address:") != -1:
                start = result.find("Address:") + 8
                end = result.find("\n", start)
                temp = result[start:end]
                if temp not in ipvs:
                    ipvs.append(result[start:end])
                result = result[end:].strip()
            results[name]['ipv4'] = ipvs
        else:
            while result.find("address ") != -1:
                start = result.find("address ") + 8
                end = result.find("\n", start)
                temp = result[start:end]
                if temp not in ipvs:
                    ipvs.append(result[start:end])
                result = result[end:].strip()
            results[name]['ipv6'] = ipvs

def http_helper(name, counter=0):
    if counter < 10:
        secure = False
        if "https" in name:
            secure = True

        if secure:
            connect = http.client.HTTPSConnection(name, timeout=5)
        else:
            connect = http.client.HTTPConnection(name, timeout=5)
        
        try:
            connect.request("GET", "/", headers={"Host": name})
            response = connect.getresponse()

            
                print('Redirect: ', name, line)
                
                http_helper(name, True, counter+1)
                # server 5.4
        except:
            return False
        
            # if response.status[0:2] == '30':
            # print("Name", name, "Status", response.status, response.reason)
    

def http_scanner(name):
    server = None
    insecure = True
    redirect = False

    
    
    connect = http.client.HTTPConnection(name, timeout=5)
    try:
        connect.request("GET", "/", headers={"Host": name})
        response = connect.getresponse()
        #print("Response", response.msg)
        if response.status[0:2] == '30':
            msg = response.msg.as_string()
            loc = msg.find("Location:")
            start = msg[loc + 10:]
            end = start.find('\n')
            new_name = start[:end]
            new_response = http_helper(new_name)
        
        for line in response.msg.as_string().splitlines():
            #print(line)
            if "Server:" in line:
                server = line[line.find('Server:') + 8 :].strip()
                print("Name", name, line)
                break

            # if "Location" in line:
            #     if counter < 10:
            #         print('Redirect: ', name, line)
                    
            #         http_helper(name, True, counter+1)
            # server 5.4
    except:
        print("Insecure", name)
        insecure = False
    
    if insecure:
        if response.status[0:2] == '30':
            loc = response.msg.find("Location:")
            if loc != -1:
                msg = response.msg[loc + 10:]
                new_name_loc = msg.find("http")
                if "https" in msg

                if sec_loc == -1:
                    sec = False
                else:
                    sec = True
                    new
            sec = True if response
            
            print("Name", name, "Status", response.status, response.reason)
    results[name]['http_server'] = server
    results[name]['insecure_http'] = insecure

    #response.status response.reason i.e 404 not found
if __name__ == "__main__":
    main()

#subprocess.check_output(["nslookup", "northwestern.edu", "8.8.8.8"], timeout = 2, stderr = subprocess.STDOUT).decode("utf-8")
#'Server:\t\t8.8.8.8\nAddress:\t8.8.8.8#53\n\nNon-authoritative answer:\nName:\tnorthwestern.edu\nAddress: 129.105.136.48\n\n'