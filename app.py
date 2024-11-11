from flask import Flask, request
import base64
import gzip
import json
import logging
import os 
import requests
import datetime
import hashlib
import hmac


app = Flask(__name__)

WORKSPACE_ID = os.environ.get('WORKSPACE_ID')
SHARED_KEY = os.environ.get('SHARED_KEY')

if (WORKSPACE_ID is None or SHARED_KEY is None):
    print("ERROR: Missing WORKSPACE_ID or SHARED_KEY")
    raise Exception("Please add azure sentinel customer_id and shared_key to azure key vault/application settings of web app") 
# modified the original code to not use the workspace id
# and shared key from the environment variables as this would
# expose them to strata which is not appropriate
BASIC_AUTH_USERNAME = os.environ.get('BASIC_AUTH_USERNAME')
BASIC_AUTH_PASSWORD = os.environ.get('BASIC_AUTH_PASSWORD')

if (BASIC_AUTH_USERNAME is None or BASIC_AUTH_PASSWORD is None):
    print("ERROR: Missing BASIC_AUTH_USERNAME or BASIC_AUTH_PASSWORD")
    raise Exception("Please add basic auth username and password to azure key vault/application settings of web app")

BASIC_AUTH = base64.b64encode("{}:{}".format(BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD).encode()).decode("utf-8")
LOG_TYPE = 'Log-Type'
HTTPS = 'https://'
AZURE_URL = '.ods.opinsights.azure.com'
AZURE_API_VERSION = '?api-version=2016-04-01'
RESOURCE = '/api/logs'
POST_METHOD = 'POST'
CONTENT_TYPE = 'application/json'
URI = "{}{}{}{}{}".format(HTTPS, WORKSPACE_ID, AZURE_URL, RESOURCE, AZURE_API_VERSION)
POOL = requests.Session()
POOL.mount(URI, requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=8))
FAILURE_RESPONSE = json.dumps({'success':False})
SUCCESS_RESPONSE = json.dumps({'success':True})
APPLICATION_JSON = {'ContentType':'application/json'}

class UnAuthorizedException(Exception):
    pass

class ProcessingException(Exception):
    pass

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    print("Building signature...")
    x_headers = 'x-ms-date:' + date
    string_to_hash = "{}\n{}\n{}\n{}\n{}".format(method, str(content_length), content_type, x_headers, resource)
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    print("Signature built successfully.")
    return authorization

def post(headers, body, isAuth):
    print(f"Sending POST request with auth={isAuth}...")
    auth_string = ' auth ' if isAuth else ' '
    response = POOL.post(URI, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print(f"POST request succeeded with status: {response.status_code}")
        logging.debug('accepted {}'.format(auth_string))
    else:
        resp_body = str(response.json())
        resp_headers = json.dumps(headers)
        failure_resp = "failure{}response details: {}{}{}".format(auth_string, response.status_code, resp_body, resp_headers)
        print(f"ERROR: POST request failed with status: {response.status_code}")
        raise ProcessingException("ProcessingException for{}: {}".format(auth_string, failure_resp)) 

def post_data(customer_id, shared_key, body, log_type, length=0):
    print("Posting data with newly generated authorization...")
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(customer_id, shared_key, rfc1123date, length, POST_METHOD, CONTENT_TYPE, RESOURCE)
    headers = {
        'content-type': CONTENT_TYPE,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    post(headers, body, False)

def post_data_auth(headers, body):
    print("Posting data with request's authorization header...")
    post(headers, body, True)

@app.route('/', methods=['POST'])
def func():
    print("Received POST request at '/' route")
    auth_headers = request.headers.get("authorization").split(",")
    body = request.get_data()
    basic_auth_header = ''
    shared_key_header = ''
    try:
        print("Processing authorization headers...")
        for auth in auth_headers:
            if "Basic" in auth:
                basic_auth_header = auth.strip()
                if (basic_auth_header.split("Basic ")[1] != BASIC_AUTH):
                    print("Unauthorized: Basic header mismatch.")
                    raise UnAuthorizedException()
            if "SharedKey" in auth:
                shared_key_header = auth.strip()

        if basic_auth_header == '':
            print("Unauthorized: Missing Basic header.")
            raise UnAuthorizedException()

        log_type = request.headers.get(LOG_TYPE)
        xms_date = ", ".join([each.strip() for each in request.headers.get('x-ms-date').split(",")]).replace("UTC", "GMT")
        headers = {
            'Content-Type': 'application/json; charset=UTF-8',
            'Authorization': shared_key_header,
            'Log-Type': log_type,
            'x-ms-date': xms_date        
        }
        print("Headers for request constructed:", headers)

        # Decompress payload
        decompressed = gzip.decompress(body)
        print("Payload decompressed successfully.")
        decomp_body_length = len(decompressed)
        if decomp_body_length == 0:
            print(f"ERROR: Decompressed body is empty. Body: {body}")
            if len(body) == 0:
              return FAILURE_RESPONSE, 400, APPLICATION_JSON 
            else:
              return FAILURE_RESPONSE, 500, APPLICATION_JSON 
        post_data_auth(headers, decompressed)
        print("Request processed with request's authorization header.")
    except ValueError as e:
        print(f"ERROR: ValueError encountered: {e}")
        return FAILURE_RESPONSE, 500, APPLICATION_JSON
    except UnAuthorizedException:
        print("ERROR: Unauthorized access attempt.")
        return FAILURE_RESPONSE, 401, APPLICATION_JSON
    except ProcessingException as e:
        print(f"ERROR: ProcessingException encountered: {e}")
        try:
            post_data(WORKSPACE_ID, SHARED_KEY, decompressed, log_type, length=decomp_body_length)
            print("Request re-processed with newly generated authorization header.")
        except ProcessingException as err:
            print(f"ERROR: Failed retry with generated authorization: {err}")
            return FAILURE_RESPONSE, 500, APPLICATION_JSON
    except Exception as e:
        print(f"ERROR: Unexpected error occurred: {e}")
        return FAILURE_RESPONSE, 500, APPLICATION_JSON

    return SUCCESS_RESPONSE, 200, APPLICATION_JSON

@app.route('/health', methods=['GET'])
def health():
    print("Received health check request.")
    return SUCCESS_RESPONSE, 200, APPLICATION_JSON

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)  # Enable detailed logging
    app.run()
