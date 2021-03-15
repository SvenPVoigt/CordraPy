import requests
from functools import wraps


def check_response(send):
    """Wrapper for the requests.Session.send method. Automatically
    checks whether request was successful and converts to json or text."""

    @wraps(send)
    def wrapper(*args, **kwargs):
        response = send(*args, **kwargs)
        if not response.ok:
            try:
                print(response.json())
            except BaseException:
                print(response.text)
            response.raise_for_status()
            return None
        else:
            try:
                return response.json()
            except BaseException:
                return response.text

    return wrapper


def get_token_value(token):
    if isinstance(token, str):
        return token
    elif isinstance(token, dict):
        try:
            return token["access_token"]
        except:
            raise Exception("Token json format error.")
    else:
        raise Exception("Token format error.")


def set_headers(token):
    if token:
        headers = dict()
        headers["Authorization"] = token_type + " " + get_token_value(token)
    else:
        headers = None
    return headers


def removeNones(obj):
    return {k: v for k, v in obj.items() if v is not None}


def get_auth(credentials_file):
    with open( credentials_file ) as loginfile:
        login = json.load(loginfile)

    data = {"grant_type":"password"}
    data.update(login)

    r = requests.post(
        "https://localhost:8443/auth/token",
        data=data,
        verify=False
    )

    if (r.ok):
        return 