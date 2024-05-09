# http-endpoint-check


## Usage
1. Install Python on your host machine. Latest version can be found [here](https://www.python.org/downloads/).
2. Install dependencies with pip 
   `pip install -r requirements.txt`

To check an endpoint run the script, passing in the URL as an arguemnt

### Example

`python3 http_endpoint_check.py https://docs.github.com/`


### next steps
- [ ] enable other HTTP status codes
- [ ] parse additional headers on auth 
- [ ] generate a list of known www-authenticate realms
- [ ] look at using playwright to automate these http checks and grab screenshots
        https://playwright.dev/python/docs/api/class-playwright
