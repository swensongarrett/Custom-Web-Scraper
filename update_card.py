import requests
import json
from urllib.parse import urljoin, unquote
import re
from typing import Optional
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_env(key: str, default: str = "") -> str:
    """Get environment variable value, returning default if not found."""
    return os.getenv(key, default)

def build_url(base: str, path: str = "") -> str:
    if not path:
        return base.rstrip('/')
    return urljoin(base.rstrip('/') + '/', path.lstrip('/'))

NYT_BASE_URL = "https://myaccount.nytimes.com"
SPREEDLY_BASE_URL = "https://core.spreedly.com"
GRAPHQL_BASE_URL = build_url(NYT_BASE_URL, "/get-started/svc/v2/graphql")
EMAIL = get_env("EMAIL")
PASSWORD = get_env("PASSWORD")
AUTH_TOKEN = get_env("AUTH_TOKEN")
NUMBER = get_env("NUMBER")
VERIFICATION_VALUE = get_env("VERIFICATION_VALUE")
FIRST_NAME = get_env("FIRST_NAME")
LAST_NAME = get_env("LAST_NAME")
MONTH = get_env("MONTH")
YEAR = get_env("YEAR")
ZIP = get_env("ZIP")
COUNTRY = get_env("COUNTRY")
SPREEDLY_CERTIFICATE_TOKEN = get_env("SPREEDLY_CERTIFICATE_TOKEN")
SPREEDLY_ENVIRONMENT_KEY = get_env("SPREEDLY_ENVIRONMENT_KEY")


def extract_next_build_id(html: str) -> Optional[str]:
    m = re.search(
        r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
        html,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if m:
        try:
            next_data = json.loads(m.group(1).strip())
            build_id = next_data.get("buildId")
            if isinstance(build_id, str) and build_id:
                return build_id
        except json.JSONDecodeError:
            pass

    m = re.search(r'/_next/static/([A-Za-z0-9\-_]+)/_buildManifest\.js', html)
    if m:
        return m.group(1)

    m = re.search(r'/_next/static/([A-Za-z0-9\-_]+)/', html)
    if m:
        return m.group(1)

    return None

session = requests.Session()
# Login
url = build_url(NYT_BASE_URL, "/svc/lire_ui/login")

payload = json.dumps({
  "username": EMAIL,
  "password": PASSWORD,
  "email": EMAIL,
  "auth_token": AUTH_TOKEN,
  "form_view": "loginWithPasswordDefault",
  "environment": "production"
})
headers = {
  'accept': 'application/json',
  'content-type': 'application/json',
  'origin': 'https://myaccount.nytimes.com',
  'referer': 'https://myaccount.nytimes.com/auth/login-password?response_type=cookie&client_id=vi&redirect_uri=https%3A%2F%2Fwww.nytimes.com%2Fsubscription%2Fonboarding-offer%3FcampaignId%3D7JFJX%26EXIT_URI%3Dhttps%253A%252F%252Fwww.nytimes.com%252F&asset=masthead',
}

response = session.post(url, headers=headers, data=payload)

print(f"Login Status: {response.status_code}")
print(f"Login Response: {response.text[:200]}")

print(f"Set-Cookie headers: {response.headers.get('Set-Cookie', 'None')}")
print(f"All response headers: {dict(response.headers)}")

print(f"Session cookies after login: {session.cookies.get_dict()}")

for cookie in response.cookies:
    print(f"Cookie from response: {cookie.name}={cookie.value} (domain={cookie.domain}, path={cookie.path})")
    session.cookies.set(cookie.name, cookie.value, domain=cookie.domain or '.nytimes.com', path=cookie.path or '/')

if response.status_code not in [200, 201]:
    raise Exception(f"Login failed with status {response.status_code}")
# Grab BUIL ID from manage billing page
url = build_url(NYT_BASE_URL, "/get-started/manage-billing/")

payload = {}
headers = {
  'accept': '*/*',
  'referer': 'https://myaccount.nytimes.com/get-started/manage-billing/credit-card',
  'x-nextjs-data': '1'
}

response = session.get(url, headers=headers, data=payload)

print(response.url)
print(response.status_code)

print("\nSession Cookies:")
print(session.cookies.get_dict())

build_id = extract_next_build_id(response.text)
print(build_id)
# Grab nonce, signature, and timestamp 
url = build_url(NYT_BASE_URL, f"/get-started/_next/data/{build_id}/manage-billing.json")
    
headers = {
    'accept': '*/*',
    'referer': 'https://myaccount.nytimes.com/get-started/manage-billing/credit-card',
    'x-nextjs-data': '1'
}

print(f"\nCookies before JSON request: {session.cookies.get_dict()}")

response = session.get(url, headers=headers)

print(f"HTTP Status Code: {response.status_code}")
print(f"HTTP Reason Phrase: {response.reason_phrase if hasattr(response, 'reason_phrase') else 'N/A'}")

data = json.loads(response.text)

if response.status_code != 200:
    print(f"\nERROR: Request failed with status code {response.status_code}")
    print(f"Response headers: {dict(response.headers)}")
    print(f"Response text (first 1000 chars): {response.text[:1000]}")
    raise Exception(f"Request failed with status code {response.status_code}. Response: {response.text[:500]}")

try:
    data = json.loads(response.text)
except json.JSONDecodeError as e:
    print(f"\nERROR: Failed to parse JSON response.")
    print(f"Response status: {response.status_code}")
    print(f"Response text (first 1000 chars): {response.text[:1000]}")
    raise Exception(f"JSON decode error: {e}. Response may be HTML or an error page.")
print("json data")
print(data)

spreedly_data = data['pageProps']['data']['account']['paymentTokens']['spreedly']
signature = spreedly_data['signature']
nonce = spreedly_data['nonce']
timestamp = spreedly_data['timestamp']

print(f"Signature: {signature}")
print(f"Nonce: {nonce}")
print(f"Timestamp: {timestamp}")
#Update card on Spreedly
url = build_url(SPREEDLY_BASE_URL, "/v1/payment_methods/restricted.json?from=iframe&v=1.179")
payload = json.dumps({
  "certificate_token": SPREEDLY_CERTIFICATE_TOKEN,
  "environment_key": SPREEDLY_ENVIRONMENT_KEY,
  "nonce": nonce,
  "payment_method": {
    "credit_card": {
      "number": NUMBER,
      "verification_value": VERIFICATION_VALUE,
      "first_name": FIRST_NAME,
      "last_name": LAST_NAME,
      "month": MONTH,
      "year": YEAR,
      "zip": ZIP,
      "country": COUNTRY
    }
  },
  "signature": signature,
  "timestamp": timestamp,
})
headers = {
  'accept': '*/*',
  'content-type': 'application/json',
  'origin': 'https://core.spreedly.com',
  'referer': 'https://core.spreedly.com/v1/embedded/number-frame-1.179.html',
  'spreedly-environment-key': SPREEDLY_ENVIRONMENT_KEY
}


response = session.post(url, headers=headers, data=payload)

print("CARD POST RESPONSE:")
print(response.text)

payment_method_token = None

if response.status_code == 201:
    try:
        response_data = json.loads(response.text)
        payment_method_token = response_data['transaction']['payment_method']['token']
        print(f"\nPayment Method Token: {payment_method_token}")
    except (KeyError, json.JSONDecodeError) as e:
        print(f"\nError extracting token: {e}")
else:
    print(f"\nRequest was not successful (Status: {response.status_code}), cannot extract token")

# Use token to verify payment
url = build_url(GRAPHQL_BASE_URL)

payload = json.dumps({
  "query": "\n    mutation VerifyPayment($payment: VerifyPayment!) {\n        verifyPayment(payment: $payment) {\n            tokenId\n            transactionState\n            transactionToken\n        }\n    }\n",
  "variables": {
    "payment": {
      "thirdPartyToken": payment_method_token,
      "tokenType": "SPREEDLY",
      "amount": "0",
      "countryCode": COUNTRY,
      "browserInfo": "",
      "scaAuthTestScenario": "",
      "isNonRecurring": False
    }
  }
})
headers = {
  'accept': 'application/json',
  'content-type': 'application/json',
  'origin': 'https://myaccount.nytimes.com',
  'referer': 'https://myaccount.nytimes.com/get-started/manage-billing/credit-card',
}

response = session.post(url, headers=headers, data=payload)

print(response.text)

response_data = json.loads(response.text)
token_id = response_data['data']['verifyPayment']['tokenId']
print(f"\nToken ID: {token_id}")
# Update card on GraphQL
url = build_url(GRAPHQL_BASE_URL)

query = """
    mutation UpdatePayment($method: Payment!, $location: Location) {
        updatePayment(method: $method, location: $location) {
        }
    }
"""

variables = {
    "method": {
        "token": payment_method_token,
        "type": "SPREEDLY",
        "tokenId": token_id,
        "cardDetails": {
            "brand": "VISA",
            "lastFour": NUMBER[-4:],
            "expirationMonth": MONTH,
            "expirationYear": YEAR,
            "firstName": FIRST_NAME,
            "lastName": LAST_NAME
        }
    },
    "location": {
        "postalCode": ZIP,
        "country": COUNTRY
    }
}

payload = {
    "query": query,
    "variables": variables
}

headers = {
    'accept': 'application/json',
    'content-type': 'application/json',
    'origin': 'https://myaccount.nytimes.com',
    'referer': 'https://myaccount.nytimes.com/get-started/manage-billing/credit-card?campaignId=8KQ79&redirect_uri=https%3A%2F%2Fwww.nytimes.com%2Faccount%2Fsubscription%3Fsource%3Dvi.mum&source=acct.act_pmt_mtd',
}

response = session.post(url, headers=headers, json=payload)

print(f"HTTP Status Code: {response.status_code}")
print(response.text)




