# Standard Library packages
from uuid import UUID
from typing import Union, Callable, Any, Dict
import json
from functools import partial
from enum import Enum

# Other Libraries
import requests
from requests import Response, Session
from pydantic import BaseModel, Field, AnyHttpUrl, Extra, FilePath

# Local imports
from .utils import check_response


# All the parameters allowed by the Cordra REST API
AllowedParams = \
    "type handle suffix dryRun full payloadToDelete jsonPointer filter".split(" ")
AllowedParams = Enum("AllowedParams", zip(AllowedParams, AllowedParams))


class Engine(BaseModel):
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

    host: AnyHttpUrl
    credentials_file: FilePath
    params: Dict[AllowedParams, Any]=Field( dict(),
        description="default parameters for Cordra Requests" )
    payloads: Dict[str, Any]=dict()
    acl: Dict=dict()
    verify: bool=True
    _session: Session=Session()
    _token: str=None
    _url: Callable=lambda self, *args: self.host + "/".join(args).replace("//", "/")
    __str__: Callable=lambda self: f"Connection via CordraPy to {self.host}"

    
    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True
        extra = Extra.allow #Options are Extra.forbid and Extra.allow not T/F


    def __init__(self, **initialization):
        super().__init__(**initialization)
        # Wrap the send function so all post, get, etc. calls check for <200>
        # Wrapper also automatically converts to dictionary format if possible
        self._session.send = check_response( self._session.send )
        self._session.verify = self.verify
        self._session.headers = {"Content-Type": "application/json"}
        if self.acl:
            self.params["full"] = True
        self._session.params = self.params

        self._auth_url = partial( self._url, "auth" )
        self._objects_url = partial( self._url, "objects" )
        self._acls_url = partial( self._url, "acls" )

        self.auth = self.get_auth()


    def get_auth(self):
        """Get a token with credentials"""

        # Open loginfile and check it is valid
        with open( self.credentials_file ) as loginfile:
            login = json.load(loginfile)
        assert login.keys() == {"username","password"}

        # Complete the Cordra auth request
        data = {"grant_type":"password"}
        data.update(login)
        print(self._auth_url("token"))
        r = self._session.post( self._auth_url("token"), data=json.dumps(data) )

        # Set up variables and default auth for future requests
        self._token = r["access_token"]
        self._session.headers.update({
            "Authorization": "Bearer " + r["access_token"]
        })


    def check_auth(self):
        """Checks an access Token"""
        data = {"token": self._token}
        params = {"full": True}
        r = self._session.post( self._auth_url("introspect"), params=params, data=data)
        return r


    def delete_auth(self):
        """Delete an access Token"""
        data = {"token": self._token}
        self._session.post( self._auth_url("revoke"), data=data)


    def create(self, obj, params=dict(), acl=None):
        """Create an object on the Cordra instance corresponding to a
        python CordraObject
        
        Attributes:
            obj: an object of type CordraObject"""

        assert isinstance(obj, CordraObject)
        assert isinstance(params, dict)

        params["type"] = obj.type

        headers = {}
        if self.payloads:  # multi-part request
            headers = {"Content-Type": "multipart/form-data"}

        data = { "content": obj.json() }
            
        if acl:
            params["full"] = True
            data.update( {"acl": json.dumps(acl) } )

        self._session.post(
            self._objects_url(), data=json.dumps(data), params=params, files=obj._payloads
        )


    def read(self, obj_id, payload=False, jsonPointer=None, jsonFilter=None):
        """Retrieve an object from Cordra by identifer and create a
        python CordraObject."""

        params["jsonPointer"] = jsonPointer
        params["filter"] = jsonFilter
        if payloads==True:
            params["payloads"] = True
        elif payloads:
            params["payloads"] = payloads
        
        r = self._session.get(self._objects_url( obj_id ), params=params)

        if payload:
            payload_info = r["payloads"]
            for payload in payload_info:
                print(payload)


        obj = CordraObject.parse_raw( r.json() )

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

        # if payloads:  # multi-part request

        data = dict()
        data["content"] = json.dumps(obj_json)
        data["acl"] = json.dumps(acl)
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


class CordraObject(BaseModel):
    type: str
    _engine: Engine=None
    _payloads: Dict=None