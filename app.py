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

# Load environment variables
WORKSPACE_ID = os.environ.get('WORKSPACE_ID')
SHARED_KEY = os.environ.get('SHARED_KEY')
BASIC_AUTH_USERNAME = os.environ.get('BASIC_AUTH_USERNAME')
BASIC_AUTH_PASSWORD = os.environ.get('BASIC_AUTH_PASSWORD')

if not all([WORKSPACE_ID, SHARED_KEY, BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD]):
    raise Exception("Ensure all environment variables are set: WORKSPACE_ID, SHARED_KEY, BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD")

# Basic auth encoding
BASIC_AUTH = base64.b64encode("{}:{}".format(BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD).encode()).decode("utf-8")
LOG_TYPE = 'Log-Type'
HTTPS = 'https://'
AZURE_URL = '.ods.opinsights.azure.com'
AZURE_API_VERSION = '?api-version=2016-04-01'
RESOURCE = '/api/logs'
POST_METHOD = 'POST'
CONTENT_TYPE = 'application/json'
URI = f"{HTTPS}{WORKSPACE_ID}{AZURE_URL}{RESOURCE}{AZURE_API_VERSION}"
POOL = requests.Session()
POOL.mount(URI, requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=10))
FAILURE_RESPONSE = json.dumps({'success': False})
SUCCESS_RESPONSE = json.dumps({'success': True})
APPLICATION_JSON = {'ContentType': 'application/json'}

# Custom exceptions
class UnAuthorizedException(Exception):
    pass


class ProcessingException(Exception):
    pass


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = f'x-ms-date:{date}'
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = string_to_hash.encode('utf-8')
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {customer_id}:{encoded_hash}"
    logging.debug(f"Generated authorization header: {authorization}")  # Log authorization header generation
    return authorization


def post(headers, body, is_auth):
    try:
        logging.debug(f"POST URI: {URI}")
        logging.debug(f"POST Headers (masked): {json.dumps({k: v if k != 'Authorization' else '***MASKED***' for k, v in headers.items()})}")
        response = POOL.post(URI, data=body, headers=headers)
        logging.debug(f"Response Code: {response.status_code}")
        logging.debug(f"Response Body: {response.text[:200]}")  # Limit body logging length to avoid excessive output
        if 200 <= response.status_code <= 299:
            logging.debug(f"Request succeeded with auth={is_auth}")
        else:
            response_content = response.json() if response.headers.get("Content-Type") == "application/json" else response.text
            logging.error(f"Request failed with status {response.status_code}: {response_content}")
            raise ProcessingException(f"Error {response.status_code}: {response_content}")
    except requests.RequestException as e:
        logging.error(f"HTTP Request failed: {str(e)}")
        raise ProcessingException("Failed to post data to Azure")


def post_data(customer_id, shared_key, body, log_type, length=0):
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(customer_id, shared_key, rfc1123date, length, POST_METHOD, CONTENT_TYPE, RESOURCE)
    headers = {
        'Content-Type': CONTENT_TYPE,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    post(headers, body, False)


def post_data_auth(headers, body):
    post(headers, body, True)


@app.route('/', methods=['POST'])
def func():
    try:
        # Retrieve and validate authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            logging.error("Missing Authorization header")
            raise UnAuthorizedException()

        # Split and check headers
        auth_headers = auth_header.split(",")
        basic_auth_header = next((h.strip() for h in auth_headers if "Basic" in h), None)
        shared_key_header = next((h.strip() for h in auth_headers if "SharedKey" in h), None)
        
        # Validate Basic Auth
        if basic_auth_header is None or basic_auth_header.split("Basic ")[1] != BASIC_AUTH:
            logging.error("Unauthorized: Basic header mismatch")
            raise UnAuthorizedException()

        if shared_key_header is None:
            logging.error("Unauthorized: Missing SharedKey header")
            raise UnAuthorizedException()

        # Retrieve required headers
        log_type = request.headers.get(LOG_TYPE)
        if not log_type:
            logging.error("Missing Log-Type header")
            return FAILURE_RESPONSE, 400, APPLICATION_JSON
        
        xms_date = request.headers.get('x-ms-date')
        if not xms_date:
            logging.error("Missing x-ms-date header")
            return FAILURE_RESPONSE, 400, APPLICATION_JSON
        
        headers = {
            'Content-Type': 'application/json; charset=UTF-8',
            'Authorization': shared_key_header,
            'Log-Type': log_type,
            'x-ms-date': xms_date.replace("UTC", "GMT")
        }

        # Process the body
        body = request.get_data()
        try:
            decompressed = gzip.decompress(body)
        except OSError:
            logging.warning("Body was not gzip compressed, using raw body")
            decompressed = body

        if not decompressed:
            logging.error("Empty decompressed body")
            return FAILURE_RESPONSE, 400, APPLICATION_JSON

        post_data_auth(headers, decompressed)
    except UnAuthorizedException:
        return FAILURE_RESPONSE, 401, APPLICATION_JSON
    except ProcessingException as e:
        logging.error(f"ProcessingException: {str(e)}")
        try:
            post_data(WORKSPACE_ID, SHARED_KEY, decompressed, log_type, length=len(decompressed))
        except ProcessingException as err:
            logging.error(f"Retry with generated auth failed: {str(err)}")
            return FAILURE_RESPONSE, 500, APPLICATION_JSON
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return FAILURE_RESPONSE, 500, APPLICATION_JSON

    return SUCCESS_RESPONSE, 200, APPLICATION_JSON


@app.route('/health', methods=['GET'])
def health():
    return SUCCESS_RESPONSE, 200, APPLICATION_JSON


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)  # Enable detailed logging
    app.run()
