# Standard Library packages
from uuid import UUID
from typing import Union
import json
from functools import partial
from copy import deepcopy

# Other Libraries
import requests
from pydantic import BaseModel, Field, AnyHttpUrl

# Local imports
from .utils import endpoint_url, check_response, set_auth, get_token_value, set_headers, removeNones
from .auth import Auth

# global variables
token_create_endpoint = "auth/token"
token_read_endpoint = "auth/introspect"
token_delete_endpoint = "auth/revoke"
token_grant_type = "password"
token_type = "Bearer"


#TODO: add CRUD tests to doctests
class Engine:
    """
    Supports CRUD operations with a running Cordra instance.

    Attributes:
        host: the location of the cordra instance (URL).
        objects_endpoint: the extension at which objects are located.
        acls_endpoint: the extension at which acls are located.

    >>> import cordra
    >>> test_object = cordra.Engine("testhost")
    >>> print(test_object)
    Connection via CordraPy to testhost
    """


    def __init__(host, params=None, payloads=None, acls=None, verify=False):
        # Constants
        self.objects_endpoint="objects/"
        self.acls_endpoint="acls/"
        
        # Variables
        self.host = host
        self.verify = verify
        self.acls = acls
        self.payloads = payloads


        # Parameter Variable
        self.params = {
            "handle":None,
            "suffix":None,
            "dryRun":False,
            "full":False,
            "payloadToDelete":None,
            "jsonPointer":None,
            "filter":None
        }

        self.allowedParams = deepcopy(self.params.keys())

        self.checkParams = lambda: self.params.keys() == self.allowedParams

        if params:
            self.params.update(params)
            assert self.checkParams() 'Invalid params argument'

        if self.params["acls"]:
            self.params["full"] = True


    def __str__():
        return "Connection via CordraPy to %s"%self.host


    def create(obj, postfunc=requests.post):
        """Create an object on the Cordra instance corresponding to a
        python CordraObject
        
        Attributes:
            obj: an object of type CordraObject"""

        assert isinstance(obj, CordraObject)

        self.params["type"] = obj.type

        if payloads:  # multi-part request
            postfunc = partial(postfunc, files=self.payloads)

        data = {
            "content": obj.json()
            "acl": json.dumps(self.params["acls"])
        }

        r = check_response(
            postfunc(
                endpoint_url(self.host, self.objects_endpoint),
                params=removeNones(self.params),
                data=removeNones(data),
                auth=set_auth(username, password),
                headers=set_headers(token),
                verify=self.verify
            )
        )

        return r


    def read(obj_id, payloads=False, jsonPointer=None, jsonFilter=None):
        """Retrieve an object from Cordra by identifer and create a
        python CordraObject."""
        
        r = check_response(
            requests.get(
                endpoint_url(self.host, self.objects_endpoint) + obj_id,
                params=self.params,
                auth=set_auth(username, password),
                headers=set_headers(token),
                verify=self.verify
            )
        )

        obj = CordraObject.parse_raw( r.json() )

        if payloads:
            payload_info = r["payloads"]
            obj.set(payload_info) = read_payload(obj_id, payload_info)

        return obj


    def read_payload(obj_id, payload_info):
        """Retrieve a Cordra object payload by identifer and payload name."""

        r = check_response(
            requests.get(
                endpoint_url(self.host, self.objects_endpoint) + obj_id,
                params=payload_info,
                auth=set_auth(username, password),
                headers=set_headers(token),
                verify=self.verify
            )
        )

        return r


    def update(obj):
        """Update a Cordra object"""

        assert obj.identifier is not None

        if payloads:  # multi-part request

        data = dict()
        data["content"] = json.dumps(obj_json)
        data["acl"] = json.dumps(acls)
            r = check_response(
                requests.put(
                    endpoint_url(host, objects_endpoint) + obj_id,
                    params=params,
                    files=payloads,
                    data=data,
                    auth=set_auth(username, password),
                    headers=set_headers(token),
                    verify=verify,
                )
            )
            return r
        elif acls:  # just update ACLs
            r = check_response(
                requests.put(
                    endpoint_url(host, acls_endpoint) + obj_id,
                    params=params,
                    data=json.dumps(acls),
                    auth=set_auth(username, password),
                    headers=set_headers(token),
                    verify=verify,
                )
            )
            return r
        else:  # just update object
            if not obj_json:
                raise Exception("obj_json is required")
            r = check_response(
                requests.put(
                    endpoint_url(host, objects_endpoint) + obj_id,
                    params=params,
                    data=json.dumps(obj_json),
                    auth=set_auth(username, password),
                    headers=set_headers(token),
                    verify=verify,
                )
            )
            return r

    def delete(
        host,
        obj_id,
        jsonPointer=None,
        username=None,
        password=None,
        token=None,
        verify=None,
    ):
        """Delete a Cordra object"""

        params = dict()
        if jsonPointer:
            params["jsonPointer"] = jsonPointer

        r = check_response(
            requests.delete(
                endpoint_url(host, objects_endpoint) + obj_id,
                params=params,
                auth=set_auth(username, password),
                headers=set_headers(token),
                verify=verify,
            )
        )
        return r

    def find(
        host,
        query,
        username=None,
        password=None,
        token=None,
        verify=None,
        ids=False,
        jsonFilter=None,
        full=False,
    ):
        """Find a Cordra object by query"""

        params = dict()
        params["query"] = query
        params["full"] = full
        if jsonFilter:
            params["filter"] = str(jsonFilter)
        if ids:
            params["ids"] = True
        r = check_response(
            requests.get(
                endpoint_url(host, objects_endpoint),
                params=params,
                auth=set_auth(username, password),
                headers=set_headers(token),
                verify=verify,
            )
        )
        return r


class Token:
    def create(host, username, password, verify=None, full=False):
        """Create an access Token"""

        params = dict()
        params["full"] = full

        auth_json = dict()
        auth_json["grant_type"] = token_grant_type
        auth_json["username"] = username
        auth_json["password"] = password

        r = check_response(
            requests.post(
                endpoint_url(host, token_create_endpoint),
                params=params,
                data=auth_json,
                verify=verify,
            )
        )
        return r

    def read(host, token, verify=None, full=False):
        """Read an access Token"""

        params = dict()
        params["full"] = full

        auth_json = dict()
        auth_json["token"] = get_token_value(token)

        r = check_response(
            requests.post(
                endpoint_url(host, token_read_endpoint),
                params=params,
                data=auth_json,
                verify=verify,
            )
        )
        return r

    def delete(host, token, verify=None):
        """Delete an access Token"""

        auth_json = dict()
        auth_json["token"] = get_token_value(token)

        r = check_response(
            requests.post(
                endpoint_url(host, token_delete_endpoint), data=auth_json, verify=verify
            )
        )
        return r
