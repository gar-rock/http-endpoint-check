import sys
import requests
import json

import math

import www_authenticate
import argparse
import urllib.parse
import re


parser=argparse.ArgumentParser(description="HTTP Endpoint Check")
parser.add_argument('-r', action='store_true', help="return raw output from urls")
parser.add_argument("urls", help="list of urls to check")

raw_output = False


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def convert_size(size_bytes):
    size_bytes = int(size_bytes)
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1000)))
    p = math.pow(1000, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
}
# headers = {
#     "User-Agent": "PostmanRuntime/7.37.3",
#     "Content-Type":"application/json",
#     "Content-Length": "77",
#     "Accept": "*/*",
# }




def check_auth_on_300(response):

    #document various scenarios, start from the known auth attributes, look for headers and codes
    #then parse everything else
    #print(response)

    headers = response.headers
    location = urllib.parse.unquote(headers["Location"])
    #print(location)

    #saml keywords for HTTP binding using SAML 2.0
    # according to https://sagarag.medium.com/reloading-saml-saml-basics-b8999995c73e
    saml_kws = ["sso","saml","samlrequest","relaystate","samlencoding","sigalg"]
    if any(ext in location.lower() for ext in saml_kws):
        #This is saml redirect HTTP binding
        # try to extract this info
        # Regular expressions to extract SAMLRequest, RelayState, and IDP
        saml_request_pattern = r"SAMLRequest=([^&]+)"
        relay_state_pattern = r"RelayState=([^&]+)"
        idp_pattern = r"=([^&]+)?SAMLRequest"

        # Extracting values using regular expressions
        saml_request =  urllib.parse.unquote(re.search(saml_request_pattern, location).group(1))
        relay_state =  urllib.parse.unquote(re.search(relay_state_pattern, location).group(1))
        idp =  urllib.parse.unquote(re.search(idp_pattern, location).group(1))

        if raw_output:
            print("SAMLRequest:", saml_request)
            print("RelayState:", relay_state)
            print("IDP:", idp)

        return f"SAML Auth","SAML SSO",f"HTTP SAML Binding found. Identity Provider is {idp}"



    #print(response.headers)
    # look for oidc
    if "Set-Cookie" in headers:
        if "oidc_id_token" in headers["Set-Cookie"]:
            return "OIDC Auth","OAUTH","OAuth found."


def check_auth_type_on_400(response):

    #document various scenarios, start from the known auth attributes, look for headers and codes
    #then parse everything else
    #print(response)

    headers = response.headers

    #print(response.headers)

    if "x-amz-apigw-id" in headers and response.status_code == 403:
        return "Amazon AWS","API Gateway","You need an API key, likely in header as x-api-key. See more info at https://aws.amazon.com/what-is/api-key/"
    if "WWW-Authenticate" in headers:
        parsed_www_auth = www_authenticate.parse(headers['WWW-Authenticate'])
        realm = ''
        challenge = ''
        if 'Basic' in parsed_www_auth:
            realm = parsed_www_auth['Basic']['realm']
            challenge = "Basic"
        if 'Negotiate' in parsed_www_auth:
            challenge = parsed_www_auth['Negotiate']
        
        # print()
        # print(parsed_www_auth)
        # print()

        return realm,f"{realm} Auth Endpoint",f"The endpoint is asking for {challenge} Auth. See more info at https://datatracker.ietf.org/doc/html/draft-ietf-http-authentication-03#section-2"
   


def main(urls):

    for url in urls:
        print()
        try:
            """

            ## GET ##
            
            """
            r = requests.get(url, verify=True, allow_redirects=False, headers=headers)
            if r.status_code == 200:
                output = r.content
                print(
                    f"{bcolors.OKGREEN}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.OKGREEN}is alive!{bcolors.ENDC}"
                )
                if "html" in str(output):
                    print("     Type: HTML")
                if "xml" in str(output):
                    print("     Type: XML")
                try:
                    _json = json.loads(str(output))
                    print("     Type: JSON")
                except:
                    pass
                print("     size: " + str(convert_size(sys.getsizeof(output))))
                # print(f"\n{output}")
            elif r.status_code == 301:
                source,name,description = check_auth_on_300(r)
                redirect_location = r.headers["location"]
                redirect_location_short = redirect_location.split("?")[0]
                print(
                    f"{bcolors.WARNING}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.WARNING}redirects to{bcolors.ENDC} {bcolors.BOLD}{redirect_location_short}{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}"
                )
            elif r.status_code == 302:
                source,name,description = check_auth_on_300(r)
                redirect_location = r.headers["location"]
                redirect_location_short = redirect_location.split("?")[0]
                print(
                    f"{bcolors.WARNING}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.WARNING}redirects to{bcolors.ENDC} {bcolors.BOLD}{redirect_location_short}{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}"
                )
            elif r.status_code == 401:
                source,name,description = check_auth_type_on_400(r)
                print(
                    f"{bcolors.FAIL}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}Unauthorized{bcolors.ENDC} {bcolors.BOLD}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}"
                )

            elif r.status_code == 403:
                source,name,description = check_auth_type_on_400(r)
                print(
                    f"{bcolors.FAIL}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}Forbidden{bcolors.ENDC} {bcolors.BOLD}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}"
                )
                print(
                    f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}"
                )
            else:
                print(f"Status Code: {r.status_code}")
        except requests.exceptions.ConnectionError as errc:
            print(
                f"{bcolors.FAIL}[ERROR]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}refused connection{bcolors.ENDC}"
            )
            print("     " + str(errc))




if __name__ == "__main__":
    args=parser.parse_args()

    raw_output = args.r
    urls = (args.urls).split(",")

    main(urls)


