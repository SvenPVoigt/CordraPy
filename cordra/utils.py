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
                return response.content

    return wrapper


def pretty_print_POST(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in 
    this function because it is programmed to be pretty 
    printed and may differ from the actual request.
    """
    print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body.decode("utf-8", errors="backslashreplace"),
    ))