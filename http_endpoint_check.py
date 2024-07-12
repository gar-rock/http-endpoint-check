import sys
import requests
import json

import math

import www_authenticate
import argparse
import urllib.parse
import re


parser = argparse.ArgumentParser(description="HTTP Endpoint Check")
parser.add_argument("-r", action="store_true", help="return raw output from urls")
parser.add_argument("-l", action="store_true", default=False, help="follow redirects")
parser.add_argument(
    "-m",
    default="1",
    type=int,
    choices=range(1, 10),
    help="max number redirects",
)

parser.add_argument("urls", help="list of urls to check")

raw_output = False
follw_redirects = False
max_redirects = 1


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

    # document various scenarios, start from the known auth attributes, look for headers and codes
    # then parse everything else
    print(response)

    headers = response.headers
    location = urllib.parse.unquote(headers["Location"])
    # print(location)

    # saml keywords for HTTP binding using SAML 2.0
    # according to https://sagarag.medium.com/reloading-saml-saml-basics-b8999995c73e
    saml_kws = ["sso", "saml", "samlrequest", "relaystate", "samlencoding", "sigalg"]
    if any(ext in location.lower() for ext in saml_kws):
        # This is saml redirect HTTP binding
        # try to extract this info
        # Regular expressions to extract SAMLRequest, RelayState, and IDP

        # For inline saml soo redirect
        # print(location.lower())
        saml_request_pattern = r"SAMLRequest=([^&]+)"
        relay_state_pattern = r"RelayState=([^&]+)"
        idp_pattern = r"=([^&]+)?SAMLRequest"

        # Extracting values using regular expressions for saml request
        try:
            saml_request = urllib.parse.unquote(
                re.search(saml_request_pattern, location).group(1)
            )
            relay_state = urllib.parse.unquote(
                re.search(relay_state_pattern, location).group(1)
            )
            idp = urllib.parse.unquote(re.search(idp_pattern, location).group(1))
        except:
            saml_request = "none"
            relay_state = "none"
            idp = "none"
        if raw_output:
            print("SAMLRequest:", saml_request)
            print("RelayState:", relay_state)
            print("IDP:", idp)

        # for ping the location for idp intiated has this in the url
        ping_intiated_kws = ["startsso.ping"]
        # and for sp initiated it's this
        sp_initiated_kws = ["/idp/sso.saml2"]
        if any(ext in location.lower() for ext in ping_intiated_kws):
            idp = "pingidentity"
            return f"SAML Auth", "SAML SSO", f"Identity Provider initiated {idp}"
        elif any(ext in location.lower() for ext in sp_initiated_kws):
            return (
                f"SAML Auth",
                "SAML SSO",
                f"HTTP SAML Binding found, Service Provider initiated. IdP is {idp}",
            )
        else:
            idp = "unknown"
            return f"SAML Auth", "SAML SSO", f"Identity Provider {idp}"

    # print(response.headers)
    # look for oidc
    if "Set-Cookie" in headers:
        if "oidc_id_token" in headers["Set-Cookie"]:
            return "OIDC Auth", "OAUTH", "OAuth found."


def check_auth_type_on_400(response):

    # document various scenarios, start from the known auth attributes, look for headers and codes
    # then parse everything else
    # print(response)

    headers = response.headers

    # print(response.headers)

    if "x-amz-apigw-id" in headers and response.status_code == 403:
        return (
            "Amazon AWS",
            "API Gateway",
            "You need an API key, likely in header as x-api-key. See more info at https://aws.amazon.com/what-is/api-key/",
        )
    if "WWW-Authenticate" in headers:
        parsed_www_auth = www_authenticate.parse(headers["WWW-Authenticate"])
        realm = ""
        challenge = ""
        if "Basic" in parsed_www_auth:
            realm = parsed_www_auth["Basic"]["realm"]
            challenge = "Basic"
        if "Negotiate" in parsed_www_auth:
            challenge = parsed_www_auth["Negotiate"]

        # print()
        # print(parsed_www_auth)
        # print()

        return (
            realm,
            f"{realm} Auth Endpoint",
            f"The endpoint is asking for {challenge} Auth. See more info at https://datatracker.ietf.org/doc/html/draft-ietf-http-authentication-03#section-2",
        )


def test_http_endpoint(url, current_redirect):
    if current_redirect < 0:
        return False
    current_redirect = current_redirect - 1
    try:
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
            return False
        elif r.status_code == 301:
            source, name, description = check_auth_on_300(r)
            redirect_location = r.headers["location"]
            redirect_location_short = redirect_location.split("?")[0]
            print(
                f"{bcolors.WARNING}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.WARNING}redirects to{bcolors.ENDC} {bcolors.BOLD}{redirect_location_short}{bcolors.ENDC}"
            )
            print(f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}")
            print(redirect_location_short)

            return test_http_endpoint(redirect_location, current_redirect)
        elif r.status_code == 302:
            source, name, description = check_auth_on_300(r)
            redirect_location = r.headers["location"]
            redirect_location_short = redirect_location.split("?")[0]
            print(
                f"{bcolors.WARNING}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.WARNING}redirects to{bcolors.ENDC} {bcolors.BOLD}{redirect_location_short}{bcolors.ENDC}"
            )
            print(f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}")
            print(redirect_location_short)

            return test_http_endpoint(redirect_location, current_redirect)
        elif r.status_code == 401:
            source, name, description = check_auth_type_on_400(r)
            print(
                f"{bcolors.FAIL}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}Unauthorized{bcolors.ENDC} {bcolors.BOLD}"
            )
            print(f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}")
            return False
        elif r.status_code == 403:
            source, name, description = check_auth_type_on_400(r)
            print(
                f"{bcolors.FAIL}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}Forbidden{bcolors.ENDC} {bcolors.BOLD}"
            )
            print(f"  {bcolors.OKCYAN}[{source}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{name}]{bcolors.ENDC}")
            print(f"  {bcolors.OKCYAN}[{description}]{bcolors.ENDC}")
            return False
        else:
            print(f"Status Code: {r.status_code}")
            return False
    except requests.exceptions.ConnectionError as errc:
        print(
            f"{bcolors.FAIL}[ERROR]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}refused connection{bcolors.ENDC}"
        )
        print("     " + str(errc))
        return False
    return False


def main(urls):

    for url in urls:
        print(url)

        """

        ## GET ##
        
        """
        # make this recursive up until the max amount of redirects
        # follw_redirects will be the boolean to check, otherwise don't do while
        # maybe make a funciton with a yield? not sure...
        requests = []
        if args.l:
            test_http_endpoint(url, max_redirects)
        else:
            test_http_endpoint(url, 0)


if __name__ == "__main__":
    args = parser.parse_args()
    raw_output = args.r
    follw_redirects = args.l
    max_redirects = args.m
    urls = (args.urls).split(",")

    main(urls)
