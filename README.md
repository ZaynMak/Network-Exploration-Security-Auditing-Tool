# Network Exploration and Security Auditing Tool

## Overview
In this project, we set out to develop a comprehensive tool for network exploration and security auditing. Our objective was to create a tool that takes a list of domains as input, conducts probes using different methods, and generates detailed reports on each domain's network and security attributes.

## Part 1: Scanner Framework
We developed a Python 3 program that takes a list of web domains as input and produces a human-readable JSON dictionary containing information about each domain. The provided example output served as a guide for the expected format.

### Usage
```bash
$ python3 scan.py [input_file.txt] [output_file.json]
```

We ensured the human-readable output with proper indentation using the provided code snippet. Additionally, we included a `requirements.txt` file as we utilized third-party libraries.

## Part 2: Network Scanners
We implemented various network scanners, each contributing specific information to the final domain report. We adhered to the provided specifications for each scanner, considering factors such as error handling, platform independence, and result consistency. _For some of the scanners we were unable to run it on our devices, so we ran it on MOORE which is a server class machines running Linux._

### Contribution to the Report

#### 2.1 Scan Time
We recorded the time when scanning starts, expressed in UNIX epoch seconds.

#### 2.2 IPv4 Addresses
We listed IPv4 addresses listed as DNS "A" records for the domain.

#### 2.3 IPv6 Addresses
We listed IPv6 addresses listed as DNS "AAAA" records for the domain.

#### 2.4 HTTP Server
We identified the web server software reported in the Server header of the HTTP response.

#### 2.5 Insecure HTTP
We indicated whether the website listens for unencrypted HTTP requests on port 80.

#### 2.6 Redirect to HTTPS
We indicated whether unencrypted HTTP requests on port 80 are redirected to HTTPS requests on port 443.

#### 2.7 HSTS
We indicated whether the website has enabled HTTP Strict Transport Security.

#### 2.8 TLS Versions
We listed all versions of Transport Layer Security (TLS/SSL) supported by the server.

#### 2.9 Root CA
We listed the root certificate authority (CA) at the base of the chain of trust for validating this server’s public key.

#### 2.10 RDNS Names
We listed reverse DNS names for the IPv4 addresses.

#### 2.11 RTT Range
We reported the shortest and longest round trip time (RTT) when contacting all the IPv4 addresses.

#### 2.12 Geo Locations
We listed the set of real-world locations (city, province, country) for all the IPv4 addresses.

## Part 3: Report
In this section, we developed a Python script (`report.py`) that prints an ASCII text report summarizing the results from Part 2. The script takes a JSON file as input and generates a text report. The report includes:

1. A textual or tabular listing of all the information returned in Part 2, with a section for each domain.
2. A table showing the RTT ranges for all domains, sorted by the minimum RTT (ordered from fastest to slowest).
3. A table showing the number of occurrences for each observed root certificate authority (from “Part 2 - root ca”, Section 5.9), sorted from most popular to least.
4. A table showing the number of occurrences of each web server (from “Part 2 - http server”, Section 5.4), ordered from most popular to least.
5. A table showing the percentage of scanned domains supporting:
   - each version of TLS listed in “Part 2 - tls versions” (Section 2.8). We expect to see close to zero percent for SSLv2 and SSLv3.
   - “plain http” (“Part 2 - insecure http”, Section 2.5)
   - “https redirect” (“Part 2 - redirect to https”, Section 2.6)
   - “hsts” (“Part 2 - hsts”, Section 2.7)
   - “ipv6” (“Part 2 - ipv6 addresses”, Section 2.3)

To enhance readability and aesthetics, we utilized the texttable library.

Below are some snippets of some tables:
Table 1
+------------+-------+-----------------+-----------------+------------+------+------+------+------------+------------+-----------------+------+
|            |       |                 |                 |            | Inse | Redi |      |            |            |                 |      |
|   Domain   | Scan  |      IPv4       |      IPv6       |    HTTP    | cure | rect | HSTS |    TSL     |  Root CA   |      RDNS       | RTT  |
|            | Time  |                 |                 |   Server   | HTTP | to H |      |  Versions  |            |                 |      |
|            |       |                 |                 |            |      | TTPS |      |            |            |                 |      |
+------------+-------+-----------------+-----------------+------------+------+------+------+------------+------------+-----------------+------+
|            |       | ['205.251.242.1 |                 |            |      |      |      |            |            |                 |      |
|            |       | 03', '52.94.236 |                 |            |      |      |      |            |            |                 |      |
|            |       |     .248',      |                 |            |      |      |      |            |            |  ['s3-console-  |      |
| amazon.com | 1.701 | '54.239.28.8',  |       []        |   Server   | True | True | True | vals["tsl_ | vals["root | us-standard.con | [39, |
|            | e+09  | '54.239.28.85', |                 |            |      |      |      | versions"] |   _ca"]    | sole.aws.amazon | 50]  |
|            |       | '52.94.236.24', |                 |            |      |      |      |            |            |     .com.']     |      |
|            |       | '205.251.242.10 |                 |            |      |      |      |            |            |                 |      |
|            |       |       ']        |                 |            |      |      |      |            |            |                 |      |
+------------+-------+-----------------+-----------------+------------+------+------+------+------------+------------+-----------------+------+
|  asee.org  | 1.701 | ['20.49.104.4'] |       []        | Microsoft- | True | True | Fals | vals["tsl_ | vals["root |       []        | [32, |
|            | e+09  |                 |                 |  IIS/10.0  |      |      |  e   | versions"] |   _ca"]    |                 | 32]  |
+------------+-------+-----------------+-----------------+------------+------+------+------+------------+------------+-----------------+------+

Table 2
+----------------------------+-----------+
|           Domain           |    RTT    |
+----------------------------+-----------+
|        clocktab.com        | [10, 15]  |
+----------------------------+-----------+
|          kli.org           | [10, 22]  |
+----------------------------+-----------+
|         reddit.com         | [10, 28]  |
+----------------------------+-----------+
|          yelp.com          | [11, 121] |
+----------------------------+-----------+

Table 4
+-------------------------------------------------+----------------------------+
|                     Domain                      | Root Certificate Authority |
+-------------------------------------------------+----------------------------+
|                      None                       |             5              |
+-------------------------------------------------+----------------------------+
|                     Apache                      |             3              |
+-------------------------------------------------+----------------------------+
|                      envoy                      |             2              |
+-------------------------------------------------+----------------------------+

Table 5
+----------------+------------+
|  Support for   | Percentage |
+----------------+------------+
| HTTP Redirects |   0.893    |
+----------------+------------+
|      HSTS      |   0.393    |
+----------------+------------+
