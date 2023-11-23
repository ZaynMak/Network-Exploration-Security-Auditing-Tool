import time, sys, json

results = {}
def main():
    file_in = sys.argv[1]
    file_out = sys.argv[2]

    
    read_file = open(file_in, "r")
    for line in read_file:
        line = line.strip()
        #   print(line + " is being scanned")
        results[line]={'scan_ time': time.time()}
        #call other scanners for each website
    # print(results)
    
    with open (file_out, "w" ) as f:
        json.dump(results, f, sort_keys = True, indent=4)
    # file_out.write(json_obj)
    file_out.close()
    read_file.close()
    



if __name__ == "__main__":
    main()