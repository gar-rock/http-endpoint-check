import sys
import requests
import json

import math


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



weburlURL = sys.argv[1:]
for url in weburlURL:
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
            redirect_location = r.headers["location"]
            redirect_location_short = redirect_location.split("?")[0]
            print(
                f"{bcolors.WARNING}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.WARNING}redirects to{bcolors.ENDC} {bcolors.BOLD}{redirect_location_short}{bcolors.ENDC}"
            )
        elif r.status_code == 302:
            redirect_location = r.headers["location"]
            redirect_location_short = redirect_location.split("?")[0]
            print(
                f"{bcolors.WARNING}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.WARNING}redirects to{bcolors.ENDC} {bcolors.BOLD}{redirect_location_short}{bcolors.ENDC}"
            )
        elif r.status_code == 401:
            redirect_location = r.headers["location"]
            redirect_location_short = redirect_location.split("?")[0]
            print(
                f"{bcolors.FAIL}[{r.status_code}]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}Unauthorized{bcolors.ENDC} {bcolors.BOLD}"
            )
        else:
            print(f"Status Code: {r.status_code}")
    except requests.exceptions.ConnectionError as errc:
        print(
            f"{bcolors.FAIL}[ERROR]{bcolors.ENDC} {bcolors.BOLD}{url}{bcolors.ENDC} {bcolors.FAIL}refused connection{bcolors.ENDC}"
        )
        print("     " + str(errc))
