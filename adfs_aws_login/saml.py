import base64
import re
import requests
from bs4 import BeautifulSoup
from adfs_aws_login import conf
import xml.etree.ElementTree as ET

try:
    # For Python 3.5 and later
    from urllib.parse import urlunparse
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlunparse  # noqa: F401
    from urlparse import urlparse  # noqa: F401


def _to_str(data):
    ret = data
    decode_method = getattr(data, "decode", None)
    if callable(decode_method):
        try:
            ret = data.decode()
        except:
            ret = _to_str(base64.b64encode(data))
    return str(ret)


class SamlException(Exception):
    pass


def get_saml_assertion(username, password, conf):
    # Initiate session handler
    print(f"starting get_saml_assertion, username: {username}, password: (not printed), conf: {conf}")
    session = requests.Session()

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    print(f"calling session get on {conf.ADFS_LOGIN_URL}, with SSL verify")
    try:
        formresponse = session.get(conf.ADFS_LOGIN_URL, verify=True)
        print(f"session.get status: {formresponse.status_code}")
    except Exception as e:
        print("got exception calling session.get:")
        print(str(e))
        raise e
    print("got form response")
    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url

    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    print(f"parsing response as XML from {idpauthformsubmiturl}")
    formsoup = BeautifulSoup(_to_str(formresponse.text), "lxml")
    payload = {}

    print("parsed response, looking for INPUT in XML")
    for inputtag in formsoup.find_all(re.compile("(INPUT|input)")):
        print(f"checking inputtag: {inputtag}")
        name = inputtag.get("name", "")
        value = inputtag.get("value", "")
        if "user" in name.lower():
            # Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            # Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            # Make an educated guess that this is the right field for the password
            payload[name] = password
        else:
            # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
            payload[name] = value
    print(f"done parsing, payload: {payload}")

    # Some IdPs don't explicitly set a form action, but if one is set we should
    # build the idpauthformsubmiturl by combining the scheme and hostname
    # from the entry url with the form action target
    # If the action tag doesn't exist, we just stick with the
    # idpauthformsubmiturl above
    print("checking for form in XML")
    for inputtag in formsoup.find_all(re.compile("(FORM|form)")):
        print(f"checking inputtag: {inputtag}")
        action = inputtag.get("action")
        loginid = inputtag.get("id")
        if action and loginid == "loginForm":
            parsedurl = urlparse(conf.ADFS_LOGIN_URL)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action
    print(f"done parsing, idpauthformsubmiturl: {idpauthformsubmiturl}")

    # Performs the submission of the IdP login form with the above post data
    print("POSTing to IDP with payload")
    response = session.post(idpauthformsubmiturl, data=payload, verify=True)

    # Overwrite and delete the credential variables, just for safety
    print("clearing memory")
    username = "##############################################"
    password = "##############################################"
    del username
    del password

    # Decode the response and extract the SAML assertion
    print(f"POST response: {response.status_code}")
    print(f"decoding SAML response: {response}")
    soup = BeautifulSoup(_to_str(response.text), "lxml")
    assertion = ""
    print(f"parsed response from {response.text}")

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    print("looking for input tag with SAMLResponse")
    for inputtag in soup.find_all("input"):
        print(f"checking inputtag: {inputtag}")
        if inputtag.get("name") == "SAMLResponse":
            print(f"checking SAMLResponse")
            assertion = inputtag.get("value")
            print(f"got {assertion}")
    print("done looking for assertion")

    # Better error handling is required for production use.
    if assertion == "":
        print("assertion is empty!")
        raise SamlException("Response did not contain a valid SAML assertion")

    # Parse the returned assertion and extract the authorized roles
    print("parsing assertion for list of roles")
    awsroles = []
    print("decoding b64")
    root = ET.fromstring(base64.b64decode(assertion))
    print(f"decoded b64 string: {root}")
    for saml2attribute in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
        print(f"checking attribute: {saml2attribute}")
        if saml2attribute.get("Name") == "https://aws.amazon.com/SAML/Attributes/Role":
            print("checking role, name matched")
            for saml2attributevalue in saml2attribute.iter(
                "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
            ):
                print("appending role to list")
                awsroles.append(saml2attributevalue.text)
    print("done looking for roles in assertion")

    print("processing roles")
    for awsrole in awsroles:
        print(f"checking role: {awsrole}")
        chunks = awsrole.split(",")
        print("checking saml-provider")
        if "saml-provider" in chunks[0]:
            print("joining chunks")
            newawsrole = chunks[1] + "," + chunks[0]
            print(f"new role: {newawsrole}")
            index = awsroles.index(awsrole)
            print(f"role found at index {index}")
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)
            print("swapped role in array")
    print("done processing, returning assertion and roles from saml.py")

    return assertion, awsroles