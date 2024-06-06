from flask import Flask, redirect, url_for, request, session, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))
    return auth

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
    return 'Welcome to the Flask SAML Authentication App'

@app.route('/saml/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    redirect_url = auth.login()
    print(f"Redirecting to SAML IdP with URL: {redirect_url}")
    return redirect(redirect_url)

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    if len(errors) == 0:
        if auth.is_authenticated():
            session['user_data'] = auth.get_attributes()
            session['name_id'] = auth.get_nameid()
            session['session_index'] = auth.get_session_index()
            print(f"User authenticated, attributes: {session['user_data']}")
            return redirect(url_for('dashboard'))
        else:
            return 'Not authenticated', 401
    else:
        print(f"Errors: {errors}")
        print(f"SAML Response: {auth.get_last_response_xml()}")
        return 'Error when processing SAML response: ' + ', '.join(errors), 400


@app.route('/dashboard')
def dashboard():
    if 'user_data' in session:
        return f"Hello, {session['user_data']}"
    else:
        return redirect(url_for('index'))

@app.route('/saml/metadata')
def saml_metadata():
    saml_settings = OneLogin_Saml2_Settings(custom_base_path=os.path.join(os.path.dirname(__file__), 'saml'))
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
        return resp
    else:
        return 'Error in metadata', 500

@app.route('/saml/slo')
def saml_slo():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    name_id = session.get('name_id')
    session_index = session.get('session_index')
    if name_id and session_index:
        logout_request = auth.logout(name_id=name_id, session_index=session_index)
        print(f"Initiating SAML logout, redirecting to: {logout_request}")
        return redirect(logout_request)
    else:
        return redirect(url_for('index'))

@app.route('/saml/sls')
def saml_sls():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    url = auth.process_slo(delete_session_cb=lambda: session.clear())
    errors = auth.get_errors()
    if len(errors) == 0:
        if url is not None:
            return redirect(url)
        else:
            return redirect(url_for('index'))
    else:
        print(f"Errors during SAML logout: {errors}")
        return 'Error when processing SAML logout: ' + ', '.join(errors), 400

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
