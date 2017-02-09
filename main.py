import os
import json
import requests
import base64

from flask import Flask, request, session, send_from_directory, redirect, make_response
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning

requests.packages.urllib3.disable_warnings((InsecurePlatformWarning, SNIMissingWarning))

"""
GLOBAL VARIABLES ########################################################################################################
"""
app = Flask(__name__)
app.secret_key = "6w_#w*~AVts3!*yd&C]jP0(x_1ssd]MVgzfAw8%fF+c@|ih0s1H&yZQC&-u~O[--"  # For the session

okta_org = "https://myorg.okta.com"
okta_api_token = "okta api token"
okta_oauth_client_id = "okta oauth client id"
okta_oauth_client_secret = "okta oauth clientsecret"
okta_redirect_uri="my redirect uri"


"""
UTILS ###################################################################################################################
"""


def execute_post(url, body, headers):
    print "execute_post()"
    print "url: %s" % url
    print "body: %s" % body
    print "headers: %s" % headers

    rest_response = requests.post(url, headers=headers, json=body)
    response_json = rest_response.json()

    print "json: %s" % json.dumps(response_json, indent=4, sort_keys=True)
    return response_json


def get_session_token(username, password):
    print("get_session_token()")
    url = "{host}/api/v1/authn".format(host=okta_org)

    header = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "SSWS {api_token}".format(api_token=okta_api_token),
        "User-Agent": request.headers["User-Agent"],
        "X-Forwarded-For": request.headers["X-Forwarded-For"],
        "X-Forwarded-Port": request.headers["X-Forwarded-Port"],
        "X-Forwarded-Proto": request.headers["X-Forwarded-Proto"]
    }

    body = {
        "username": username,
        "password": password
    }

    authn_reponse_json = execute_post(url, body, header)

    if("errorSummary" in authn_reponse_json):
        raise ValueError(authn_reponse_json["errorSummary"])

    return authn_reponse_json["sessionToken"]

def create_oidc_auth_code_url(session_token):
    url = (
        "{host}/oauth2/v1/authorize?"
        "response_type=code&"
        "client_id={clint_id}&"
        "redirect_uri={redirect_uri}&"
        "state=af0ifjsldkj&"
        "nonce=n-0S6_WzA2Mj&"
        "response_mode=form_post&"
        "prompt=none&"
        "scope=openid&"
        "sessionToken={session_token}"
    ).format(
        host=okta_org,
        clint_id=okta_oauth_client_id,
        redirect_uri=okta_redirect_uri,
        session_token=session_token
    )
    return url


def get_oauth_token(oauth_code):

    url = (
        "{host}/oauth2/v1/token?"
        "grant_type=authorization_code&"
        "code={code}&"
        "redirect_uri={redirect_uri}"
    ).format(
        host=okta_org,
        code=oauth_code,
        redirect_uri=okta_redirect_uri
    )

    auth_raw = "{client_id}:{client_secret}".format(
                        client_id=okta_oauth_client_id,
                        client_secret=okta_oauth_client_secret
                    )

    print "auth_raw: %s" % auth_raw
    encoded_auth = base64.b64encode(auth_raw)
    print "encoded_auth: %s" % encoded_auth

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic {encoded_auth}".format(encoded_auth=encoded_auth)
    }

    body = {
        "authorization_code": oauth_code
    }

    oauth_token_response_json = execute_post(url, body, headers)

    return oauth_token_response_json["access_token"]

"""
ROUTES ##################################################################################################################
"""


@app.route("/login", methods=["POST"])
def login():
    print "login()"

    # Authenticate via Okta API to get Session Token
    user = request.form["email"]
    password = request.form["password"]
    session_token = None
    try:
        session_token = get_session_token(username=user, password=password)
    except ValueError as err:
        print(err.args)

    print "session_token: %s" % session_token

    # Use Session Token to generatet OIDC Auth Code URL
    if(session_token):
        oidc_auth_code_url = create_oidc_auth_code_url(session_token)
        print "url: %s" % oidc_auth_code_url
        # redirect to User Auth Code URL to Get OIDC Code
        return redirect(oidc_auth_code_url)

    else:
        return serve_static_html("login.html");


@app.route("/oidc", methods=["POST"])
def oidc():
    print "oidc()"
    print request.form
    oidc_code = request.form["code"]
    print "oidc_code: %s" % oidc_code
    oauth_token = get_oauth_token(oidc_code)

    response = make_response(redirect('index.html'))
    response.set_cookie('token', oauth_token)
    return response


@app.route("/", methods=["GET"])
def root():
    return app.send_static_file("index.html")


@app.route('/<path:filename>')
def serve_static_html(filename):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route('/fonts/<path:filename>')
def serve_static_fonts(filename):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static', 'fonts'), filename)


@app.route('/js/<path:filename>')
def serve_static_js(filename):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static', 'js'), filename)


@app.route('/css/<path:filename>')
def serve_static_css(filename):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static', 'css'), filename)


@app.route('/images/<path:filename>')
def serve_static_images(filename):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static', 'images'), filename)


if __name__ == "__main__":
    # This is to run on c9.io.. you may need to change or make your own runner
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)))
