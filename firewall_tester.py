#RUN THIS PROGRAM USING PYTHON 3 ONLY

# Purpose:      Test a specified website for WAF protection and check which payloads are accepted


from collections import Counter
from urllib.parse import urlparse
import requests.exceptions
import requests
import argparse
import sys
import time
import nmap
import socket

def args_parser():
    parser = argparse.ArgumentParser(
        description='Use - firewall_tester.py -u domain_name')
    required = parser.add_argument_group('!!These Arguments are required!!')
    required.add_argument('-u', '--url', help='Target URL (http://www.hackthissite.org/home.php?parameter=value)'),
    # required=True)
    parser.add_argument('-p', '--post', help='Data string to be sent through POST (parameter=value&also=another)')
    parser.add_argument('-d', '--delay', help='Set delay between requests (secends)', type=float)
    parser.add_argument('-t', '--type', help='Type of payload [sqli | xss | others]',
                        choices=['sql', 'xss', 'others', 'all'], default='all')

    # To check whether required argument is given by the user or not
    if len(sys.argv) == 0:
        parser.print_help();
        sys.exit(0)
    args=parser.parse_args()

    return args

def port_scanner():
    args=args_parser()

    if args.url:
        host=args.url
        host=host.split("//")
        host=host[1]
    else:
        print ("ERROR! Run the program again with URL of the site as Argument!! ")
        sys.exit()
    host_ip=socket.gethostbyname(host)
    port1=input("Enter the starting port : ")
    port2=input("Enter the end port : ")
    if port2>=port1:
        ports=str(port1) + '-' + str(port2)
    else:
        print ("Enter port range Correctly!")
        sys.exit()
    s = nmap.PortScanner()
    s.scan(host_ip, ports)
    for h in s.all_hosts():
        print ("\nHost: " + h + "\nState: " + s[h].state())
        print ("\n1.Show TCP only\n2.Show all")
        c=input("Enter selected choice : ")
        if int(c) == 1:
            for p in s[h].all_protocols():
                if p == 'tcp':
                    for port in s[h][p].keys():
                        print ("\nnPort: " + str(port) + "\nService: " + str(s[h][p][port]['name']) + "\nState: " + str(s[h][p][port]['state']))
        elif int(c) == 2:
            for p in s[h].all_protocols():
                for port in s[h][p].keys():
                    print ("\nnPort: " + str(port) + "\nService: " + str(s[h][p][port]['name']) + "\nState: " + str(s[h][p][port]['state']))
        else:
            print("Invalid Choice!!")


    while True:
        print ("\n1.Continue with checking firewall on this site\n2.Exit Program\n")
        ch = input("Enter Choice : ")
        if int(ch) == 2:
            sys.exit()
        elif int(ch)==1:
            break
        else:
            print("Choose Again!")


# make an argument for command line to be passed while executing this program
def main():
    args=args_parser()

    title = """
    ////////////////////////////////////////////////////////////
    //********************************************************//
    //** WELCOME TO FIREWALL TESTING PROGRAM USING PAYLOADS **//
    //********************************************************//
    ////////////////////////////////////////////////////////////"""
    print (title)

    #fetch url from the supplied argument
    if args.url:
        url = args.url
        print (" Given  URL: \n", url)
    else:
        print ("ERROR! Run the program again with URL of the site as Argument!! ")
        sys.exit()

    #required variables
    param_list = {}
    total_success = 0
    des = 0


    parsed_uri = urlparse(url)
    domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)

    if (len(url) - (len(domain) - 1)) == 0:
        url = domain

    # Check whether target URL is up or down using request module
    try:
        r = requests.get(domain,  allow_redirects=False, timeout=20)
        r.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        print ("\nOoops!!\n The Target is currently down or unreachable!")
        sys.exit()


    # Checking for header content at the time of request and attack
    header_changed = 0
    req_header = requests.get(url,  allow_redirects=False, timeout=10)
    req_header_attack = requests.get(url, params={'test': '%00'},
                                     allow_redirects=False, timeout=10)
    if req_header_attack.status_code == req_header.status_code:

        if req_header.headers.get('Content-Length'):
            len_req_header = int(len(''.join(req_header.headers.values()))) - int(
                len(req_header.headers.get('Content-Length')))
        else:
            len_req_header = int(len(''.join(req_header.headers.values())))

        if req_header_attack.headers.get('Content-Length'):
            len_req_header_attack = int(len(''.join(req_header_attack.headers.values()))) - int(
                len(req_header_attack.headers.get('Content-Length')))
        else:
            len_req_header_attack = int(len(''.join(req_header_attack.headers.values())))

    #if header content is different at the time of payload attack then this means that the website is behind a WAF security
        if len_req_header != len_req_header_attack:
            print ("\n The server seems to have changed its header content when an attack is detected. \n This means that the server is behing WAF security.")
            header_changed = 1


    if not args.post:
        if "?" in url:
            des = 1
            urls = url.split("&")
            c = len(urls)
            part_1 = urls[0].split("?")
            base_url = part_1[0]
            del urls[0]
        else:
            urls = url.split("/")
            base_url = domain
            del urls[0:3]

    if args.post:
        paramp = args.post.split("&")

    def parameters_equal(arg):
        s_arg = arg.split("=")
        param_list[s_arg[0]] = s_arg[1]
        return;

    def parameters_slash(arg, param_count):
        param_list["param_" + str(param_count)] = arg
        return;

    if not args.post:
        if des == 1:
            parameters_equal(part_1[1])
            for url in urls:
                parameters_equal(url)
        else:
            param_count = 1
            for url in urls:
                parameters_slash(url, param_count)
                param_count = param_count + 1

    if args.post:
        for param in paramp:
            parameters_equal(param)

    payloads = {}


    def file2dic(filename):
        f = open(filename, 'r')
        for line in f:
            param_split = line.rpartition('@')
            payloads[param_split[0]] = param_split[2]

    # PayloadstoDic
    if args.type == "xss":
        file2dic('payloads/XSS_Payloads.csv')
    elif args.type == "sql":
        file2dic('payloads/SQLi_Payloads.csv')
    elif args.type == "others":
        file2dic('payloads/other_Payloads.csv')
    elif args.type == "all":
        file2dic('payloads/XSS_Payloads.csv')
        file2dic('payloads/SQLi_Payloads.csv')
        file2dic('payloads/other_Payloads.csv')

    # PayloadstoDic

    for name_m, value_m in param_list.items():
        print ("\n Parameter Name : ", name_m, "\n")

        params = {}
        rs = []
        q = ""
        c = 0
        trycount = 0
        succ = 0
        fai = 0


        for payload, string in payloads.items():
            c = c + 1
            if args.delay:
                time.sleep(args.delay)
            name_m = str(name_m)
            value_m = str(value_m)
            if (payload[:1] == "\'") or (payload[:1] == "\""):
                param_list[name_m] = value_m + payload
            else:
                param_list[name_m] = value_m + "\" " + payload

            # Send-Request
            for i in range(3):
                try:
                    if args.post:
                        req = requests.post(url, data=param_list,
                                            allow_redirects=False, timeout=10)
                    else:
                        if des == 1:
                            req = requests.get(base_url, params=param_list,
                                               allow_redirects=False, timeout=10)
                        else:
                            base_url = domain
                            base_url = base_url + '/'.join(param_list.values())
                            req = requests.get(base_url,  allow_redirects=False,
                                               timeout=10)
                            base_url = domain
                    r.raise_for_status()

                    if (str(req.status_code)[0] == "2") or (str(req.status_code)[0] == "1") or (req.status_code == 404):

                        if req.headers.get('Content-Length'):
                            len_req = int(
                                len(''.join(req.headers.values())) - int(len(req.headers.get('Content-Length'))))
                        else:
                            len_req = 1

                        if not ((req.status_code == req_header_attack.status_code) and (
                                len_req == len_req_header_attack) and (header_changed == 1)):
                            string = string[:-1]
                            print (" T-R-U-E-> [", string, "][", payload, "] --> ",
                                   "\t#**SUCCESS**#\t \n Response Status: " + str(req.status_code) + "\n")
                            succ = succ + 1
                        else:
                            print ("   [", payload, "] --> ",
                                   "\t#**FAIL**#\n Response Status: " + str(req.status_code) + " ! Header was changed !\n")
                            fai = fai + 1
                    else:
                        print (
                        "   [", payload, "] --> ", "\t#**FAIL**#\n Response Status: " + str(req.status_code) + "\n")
                        fai = fai + 1

                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                    print (" [ ", payload, " ] TRYING AGAIN ..")
                    trycount = trycount + 1
                    continue
                else:
                    break
            else:
                print ("\n [ ", payload, " ] !!SKIPPED!!")
                continue

            rs.append(req.status_code)
            if trycount > 100:
                print (
                    "\n Either you are not connected to the internet! \nOR\n You have been blocked to access the server.\n Maybe try again later ...")
                sys.exit()
            # Send-Request
            param_list[name_m] = value_m

        # Final Output of the program
        print ("!!!! PROGRAM HAS EXECUTED SUCCESSFULLY !!!!\n !DONE!")

        total_success = rs.count(200) + rs.count(404)

        total_failed = rs.count(500) + rs.count(403) + rs.count(301) + rs.count(400) + rs.count(503) + rs.count(302)

        print ("   \nTotal Number of Payload Passed : ", c, "\n")
        count_err = Counter(rs)


        for err, err_count in count_err.items():
            print ("      \nTotal number of ", err, "errors are  \t=\t ", err_count, "\n")
        print ("      Total number of Successful Payloads :", succ, "\n")
        print ("      Total number of Failed Payloads : ", fai, "\n")
        print ("      No response from the server : ", c - (fai + succ), "\n")

    # Final Summary of all payloads

    total_success = total_success / len(param_list)
    total_failed = total_failed / len(param_list)

    if total_success >= 100:
        print ("\n   <<<<<<<<< Not a Strong WAF detected on the server >>>>>>>>>\n")
    if total_failed >= 100 and total_failed<=250:
        print ("\n   <<<<<<<<< The target is behind a Medium-strong WAF >>>>>>>>>\n")
    elif total_failed>250:
        print ("\n   <<<<<<<<< The target is behind a Strong WAF >>>>>>>>>\n")


if True:
    choice=input("\n1.Start Port Scan\n2.Start Firewall Detection program\n")
    #host = input("Enter the website name using http or https : ")
    if int(choice)==1:
        port_scanner()
        main()
    elif int(choice)==2:
        main()
    else:
        print ("Enter Option Correctly!")