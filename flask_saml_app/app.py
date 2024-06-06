from datetime import datetime, timezone,timedelta


from flask import Flask, redirect, url_for, request, session, make_response, render_template_string
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

import os
from urllib.parse import urlparse
import base64
import xml.etree.ElementTree as ET
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from urllib.parse import urlencode, urlparse
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Enforce HTTPS and adjust Content Security Policy
csp = {
    'default-src': [
        '\'self\'',
        '*.ngrok-free.app'
    ],
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        '*.ngrok-free.app'
    ]
}
talisman = Talisman(app, content_security_policy=csp)

# Apply ProxyFix to trust the headers set by ngrok
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))
    return auth


def init_saml_settings():
    return OneLogin_Saml2_Settings(custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))


def prepare_flask_request(request):
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port or ('443' if request.scheme == 'https' else '80'),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@app.route('/')
def index():
    if 'name_id' in session and 'session_index' in session:
        return redirect(url_for('dashboard'))
    else:
        return 'Welcome to the Flask SAML Authentication App'

@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)

    # Generate the AuthnRequest
    auth.login()
    
    # Get the AuthnRequest XML
    authn_request_xml = auth.get_last_request_xml()

    # Get the SP entity ID from the settings
    saml_settings = auth.get_settings()
    sp_entity_id = saml_settings.get_sp_data()['entityId']

    # Define the XML namespaces
    namespaces = {
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
    }

    # Parse the AuthnRequest XML
    tree = ET.fromstring(authn_request_xml)

    # Remove existing Issuer elements if any
    for issuer in tree.findall('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'):
        tree.remove(issuer)

    # Add the Issuer element
    issuer = ET.Element('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
    issuer.text = sp_entity_id
    tree.insert(0, issuer)

    # Remove NameIDPolicy and RequestedAuthnContext elements
    for element in tree.findall('{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy'):
        tree.remove(element)
    for element in tree.findall('{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext'):
        tree.remove(element)

    # Manually create the XML string with proper namespace prefixes
    authn_request_xml = f"""
    <samlp:AuthnRequest
        xmlns:samlp="{namespaces['samlp']}"
        xmlns:saml="{namespaces['saml']}"
        ID="{tree.get('ID')}"
        Version="2.0"
        IssueInstant="{tree.get('IssueInstant')}"
        Destination="{tree.get('Destination')}"
        ProtocolBinding="{tree.get('ProtocolBinding')}"
        AssertionConsumerServiceURL="{tree.get('AssertionConsumerServiceURL')}"
        AttributeConsumingServiceIndex="{tree.get('AttributeConsumingServiceIndex')}">
        <saml:Issuer>{sp_entity_id}</saml:Issuer>
    </samlp:AuthnRequest>
    """

    # Base64 encode the modified SAML request
    encoded_saml_request = base64.b64encode(authn_request_xml.encode('utf-8')).decode('utf-8')

    # Get the IdP SSO URL from the settings
    idp_sso_url = saml_settings.get_idp_data()['singleSignOnService']['url']

    # Create the HTML form for POST request manually
    form = f"""
    <html>
        <body>
            <form action="{idp_sso_url}" method="post" id="saml-form">
                <input type="hidden" name="SAMLRequest" value="{encoded_saml_request}"/>
                <noscript>
                    <p>Note: Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
                    <input type="submit" value="Submit"/>
                </noscript>
            </form>
            <script>
                document.getElementById('saml-form').submit();
            </script>
        </body>
    </html>
    """

    return render_template_string(form)

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if not errors:
        if auth.is_authenticated():
            session['user_data'] = auth.get_attributes()
            session['name_id'] = auth.get_nameid()
            session['session_index'] = auth.get_session_index()
            print(f"User Data: {session['user_data']}")
            print(f"NameID: {session['name_id']}")
            print(f"SessionIndex: {session['session_index']}")
            return redirect(url_for('dashboard'))
        else:
            return 'Not authenticated', 401
    else:
        return f"Error when processing SAML response: {', '.join(errors)}", 400

@app.route('/dashboard')
def dashboard():
    if 'user_data' in session:
        user_data = session['user_data']
        first_name = user_data.get('firstName', [''])[0]
        email = user_data.get('email', [''])[0]
        return f"""
            Hello, {first_name}, your email is {email}.
            <br>
            <a href="{url_for('saml_slo')}">Logout</a>
        """
    else:
        return redirect(url_for('index'))

@app.route('/saml/metadata')
def saml_metadata():
    print("New Metadata")
    saml_settings = OneLogin_Saml2_Settings(custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if not errors:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
        
        # Print the content of the resp variable for debugging (optional)
        print(resp.get_data(as_text=True))
        resp.headers['Content-Security-Policy'] = "default-src 'self' *.ngrok-free.app; style-src 'self' 'unsafe-inline';"
        return resp
    else:
        return 'Error in metadata', 500

# @app.route('/saml/slo')
# def saml_slo():
#     req = prepare_flask_request(request)
#     auth = init_saml_auth(req)
#     name_id = session.get('name_id')
#     session_index = session.get('session_index')
    
#     if name_id and session_index:
#         # Generate the SAML LogoutRequest
#         logout_request = auth.logout(name_id=name_id, session_index=session_index)
        
#         # Log the generated LogoutRequest
#         logout_request_xml = auth.get_last_request_xml()
#         print(f"Generated LogoutRequest: {logout_request_xml}")
        
#         # Store the request ID in session
#         session['LogoutRequestID'] = auth.get_last_request_id()
        
#         # Log the redirect URL
#         print(f"Redirecting to: {logout_request}")
        
#         return redirect(logout_request)
#     else:
#         return redirect(url_for('index'))

from onelogin.saml2.constants import OneLogin_Saml2_Constants
import zlib


@app.route('/saml/slo')
def saml_slo():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    name_id = session.get('name_id')
    session_index = session.get('session_index')

    if name_id and session_index:
        return_to = url_for('saml_sls', _external=True)  # SLS endpoint

        # Generate the SAML LogoutRequest with RelayState pointing to the SLS endpoint
        logout_url = auth.logout(name_id=name_id, session_index=session_index, return_to=return_to)
        
        # Log the generated LogoutRequest
        logout_request_xml = auth.get_last_request_xml()
        print(f"Generated LogoutRequest: {logout_request_xml}")
        
        # Log the redirect URL
        print(f"Redirecting to: {logout_url}")

        return redirect(logout_url)
    else:
        return redirect(url_for('index'))




@app.route('/saml/sls', methods=['POST', 'GET'])
def saml_sls():
    print("SLS is hit!")
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    request_id = session.get('LogoutRequestID')
    
    # Process the SAML LogoutResponse
    url = auth.process_slo(request_id=request_id, delete_session_cb=lambda: session.clear())
    
    # Get errors and log the SAML response
    errors = auth.get_errors()
    if errors:
        print(f"Errors during SAML logout: {errors}")
        print(f"SAML LogoutResponse: {auth.get_last_response_xml()}")
        return 'Error when processing SAML logout: ' + ', '.join(errors), 400
    
    # Log the successful logout response
    print(f"SAML LogoutResponse successfully processed: {auth.get_last_response_xml()}")
    
    if url:
        return redirect(url)
    else:
        return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
