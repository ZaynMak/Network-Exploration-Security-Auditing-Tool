import sys, json
import texttable

def main():
    file_in = sys.argv[1]
    file_out = sys.argv[2]

    read_file = open(file_in)
    file = json.load(read_file)
    vars = "scan_time", "ipv4", "ipv6", "http_server", "insecure_http", "redirect_to_https", "hsts", "tsl_versions", "root_ca", "rdns", "rtt", "geo_locations"
    #scan_time, ipv4, ipv6, http_server, insecure_http, redirect_to_https, hsts, tsl_versions, root_ca, rdns, rtt, geo_locations
    file_length = len(file)

    table1 = texttable.Texttable()
    table1.set_cols_align(["c"] * 13)
    table1.set_cols_valign(["m"] * 13)
    table1.add_row(["Domain", "Scan Time", "IPv4", "IPv6", "HTTP Server", "Insecure HTTP", "Redirect to HTTPS", "HSTS", "TSL Versions", "Root CA", "RDNS", "RTT", "Geo Locations"])

    for name in file:
        vals = file[name]
        table1.add_row([name, vals["scan_time"], vals["ipv4"], vals["ipv6"], vals["http_server"],
                        vals["insecure_http"], vals["redirect_to_https"], vals["hsts"], 'vals["tsl_versions"]',
                        'vals["root_ca"]', vals["rdns"], vals["rtt"], vals["geo_locations"]])


    table2 = texttable.Texttable()
    table2.set_cols_align(["c"] * 2)
    table2.set_cols_valign(["m"] * 2)
    table2.add_row(["Domain", "RTT"])
    print(file.items())
    sorted_rtt = sorted(file.items(), key=lambda kv: kv[1]["rtt"][0])
    print("sorted", sorted_rtt)
    for i in range(len(sorted_rtt)):
        table2.add_row(sorted_rtt[i][0], sorted_rtt[i][1]["rtt"])
    
    # Table 3
    root_pop = {}
    for name in file:
        ca = file[name]['root_ca']
        if ca in root_pop:
            root_pop[ca]+=1
        else:
            root_pop[ca] = 1
    
    table3 = texttable.Texttable()
    table3.set_cols_align(["c"] * len(root_pop))
    table3.set_cols_valign(["m"] * len(root_pop))
    table3.add_row(["Domain", "Root Certificate Authority"])
    
    for key, val in sorted(root_pop.items(), key=lambda item: item[1]):
        table3.add_row(key, val)


    # Table 4
    server_pop = {}
    for name in file:
        server = file[name]['http_server']
        if server in server_pop:
            server_pop[server]+=1
        else:
            server_pop[server] = 1
    
    table4 = texttable.Texttable()
    table4.set_cols_align(["c"] * len(server_pop))
    table4.set_cols_valign(["m"] * len(server_pop))
    table4.add_row(["Domain", "Root Certificate Authority"])
    
    for key, val in sorted(server_pop.items(), key=lambda item: item[1]):
        table4.add_row(key, val)

    # Table 5
    table5 = texttable.Texttable()
    table5.set_cols_align(["c"] * 2)
    table5.set_cols_valign(["m"] * 2)
    table5.add_row(["Support for", "Percentage"])

    supported = [0] * 6 #sslv2, sslv3, tls0, tls1, tls2, tls3

#    versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
#    for name in file:
#        supports = file[name]['tls_versions']
#        for check in range(6):
#            if versions[check] in supports:
#                supports[check]+=1 

    table5.add_row(['SSLv2', supported[0]/file_length])
    table5.add_row(['SSLv3', supported[1]/file_length])
    table5.add_row(['TLSv1.0', supported[2]/file_length])
    table5.add_row(['TLSv1.1', supported[3]/file_length])
    table5.add_row(['TLSv1.2', supported[4]/file_length])
    table5.add_row(['TLSv1.3', supported[5]/file_length])

    plain_http = sum(file.values["insecure_http"])
    https_redirect = sum(file.values["redirect_to_https"])
    hsts = sum(file.values["hsts"])
    ipv6 = sum(1 if val["ipv6"] else 0 for val in file.values())
    
    table5.add_row(["Plain HTTP", plain_http/file_length])
    table5.add_row(["HTTP Redirects", https_redirect/file_length])
    table5.add_row(["HSTS", hsts/file_length])
    table5.add_row(["IPv6", ipv6/file_length])

    print(table1.draw())
    # print()
    print(table2.draw())
    print(table3.draw())
    print(table4.draw())
    print(table5.draw())


if __name__ == "__main__":
    main()