# Standard Library packages
from uuid import UUID
from typing import Union, Callable, Any, Dict
import json
from functools import partial
from enum import Enum
from io import BytesIO
import warnings
import sys
import pickle
import os
import copy

# Other Libraries
import requests
from requests import Response, Session, Request
from pydantic import BaseModel, Field, AnyHttpUrl, Extra, FilePath, PrivateAttr

# Local imports
from .utils import check_response, pretty_print_POST


# All the parameters allowed by the Cordra REST API
createEnum = lambda L: Enum("dynamic", {str(i): val for i, val in enumerate(L)})

AllowedParams = "type handle suffix dryRun full payloadToDelete jsonPointer filter"

DefaultParams = createEnum( "handle suffix dryRun".split(" ") )
CreateParams = createEnum( "type".split(" ") )
ReadParams = createEnum( "jsonPointer filter".split(" ") )
UpdateParams = createEnum( "payloadToDelete jsonPointer filter".split(" ") )


class CordraClient(BaseModel):
    """
    Supports CRUD operations with a running Cordra instance allows access to the full 
    functionality of the Cordra REST API. This includes:
    * Authorization using user / password
    * Authorization using a secret key
    * Provide a token for subsequent authorization
    * Delete a token
    * Create a cordra object
    * Setting the ACL on a cordra object on create
    * Updating a cordra object
    * Updating a cordra object attribute
    * Updating a cordra object payload
    * Updating the ACL of a cordra object
    * Deleting a cordra object
    * Deleting a cordra object attribute
    * Deleting a cordra object payload
    * Querying cordra

    The CordraClient also provides the additional features:
    * Checking that params are valid Cordra parameters
    * Can set default params for all subsequent operations
    * The full param will always be true (not necessarily a feature)
    * Iteratively pulls all payloads for an object. 
        * Allows the user to call one read operation and retrieve all payloads
    * Reading all schemas from a remote Cordra instance and turning them into python classes
    * Default ACL always includes creator

    Attributes:
        host: the location of the cordra instance (URL).
        objects_endpoint: the extension at which objects are located.
        acls_endpoint: the extension at which acls are located.

    >>> import cordra
    >>> test_object = cordra.CordraInstance("testhost")
    >>> print(test_object)
    Connection via CordraPy to testhost
    """

    host: AnyHttpUrl
    credentials_file: FilePath
    params: Dict[DefaultParams, Any]=Field( dict(),
        description="default parameters for Cordra Requests" )
    payloads: Dict[str, Any]=dict()
    # acl: Dict=dict()
    verify: bool=True
    _session: Session=Session()
    _token: str=None
    _url: Callable=lambda self, *args: self.host + "/".join(args).replace("//", "/")
    __str__: Callable=lambda self: f"Connection via CordraPy to {self.host}"

    
    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True
        extra = Extra.allow #Options are Extra.forbid and Extra.allow not T/F
        use_enum_values = True


    def __init__(self, **initialization):
        super().__init__(**initialization)
        # Wrap the send function so all post, get, etc. calls check for <200>
        # Wrapper also automatically converts to dictionary format if possible
        self._session.send = check_response( self._session.send )
        self._session.verify = self.verify

        # Pydantic casts the keys to an enum item; must get name of enum item to
        # get back dictionary
        # Work under the assumption of full = True. Then, getting payloads is easier,
        # checking the auth is easier, need to do less checks on whether we need to
        # retrieve as content or not, etc.
        self.params.update({"full": True})
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

        r = self._session.post( self._auth_url("token"), json=data )

        # Set up variables and default auth for future requests
        self._token = r["access_token"]
        self._session.headers.update({
            "Authorization": "Bearer " + r["access_token"]
        })


    def check_auth(self):
        """Checks an access Token"""
        data = {"token": self._token}
        params = {"full": True}
        r = self._session.post( self._auth_url("introspect"), params=params, json=data)
        return r


    def delete_auth(self):
        """Delete an access Token"""
        data = {"token": self._token}
        self._session.post( self._auth_url("revoke"), json=data)


    def write(self, action, obj, params=dict(), acl=None):
        """Writes an object to the Cordra instance at the host url.
        
        Attributes:
            obj: an object of type CordraObject
            params: REST API parameters
            acl: access control list of allowed readers and writers of object.
                Updates, but doesn't overwrite, the default acl set on the client."""

        assert isinstance(obj, CordraObject)
        assert isinstance(params, dict)

        # Multi-Part Form
        if len(obj._payloads) > 0:
            data = { "content": obj.json() }
            files = { 
                name: (filename, BytesIO(filebytes)) 
                for name, (filename, filebytes) in obj._payloads.items() 
            }

            return action(params=params, data=data, files=files)

        return action(params=params, json=obj.dict(exclude_none=True))


    def create(self, obj, params=dict(), acl=None):
        """Uses write to create and object"""

        params["type"] = obj.type

        # if acl or self.acl:
        #     tmp_acl = dict(self.acl)
        #     tmp_acl.update(acl)
        #     data.update( {"acl": json.dumps(tmp_acl) } )

        # print(obj)

        action = partial( self._session.post, url=self._objects_url() )

        return self.write(action, obj, params, acl)


    def update(self, obj, params=dict(), updatePayloads=True, acl=None):
        """Uses write to update an object"""

        assert obj.id is not None, "CordraObject needs id to update"

        params["type"] = obj.type
        action = partial( self._session.put, url=self._objects_url(obj.id) )

        update_obj = obj.copy()

        if not updatePayloads:
            setattr( update_obj, "_payloads", dict() )

        return self.write(action, update_obj, params, acl)


    def read(self, obj_id, params=dict(), getAll=False):
        """Retrieve an object from Cordra by identifer and create a
        python CordraObject."""

        # Can add a jsonPointer, filter, and payload key
        assert isinstance(params, dict)

        if "payload" in params.keys():
            assert isinstance(params["payload"], str)
        
            return self._session.get(self._objects_url( obj_id ), params=params)

        # print(obj_id, params)
        r = self._session.get(self._objects_url( obj_id ), params=params)
        # print(json.dumps(r, indent=2))
        obj = CordraObject.parse_obj(r['content'])
        obj.id = r["id"]

        if getAll:
            for payload in r["payloads"]:
                r = self.read(obj_id, params={"payload": payload["name"]})

                if isinstance(r, str):
                    r = r.encode()
                elif isinstance(r, dict):
                    r = json.dumps(r).encode()
                elif isinstance(r, bytes):
                    pass
                else:
                    raise ValueError(f"Response content for payload, {payload['name']} is not of an acceptable type. Accepted types include (str, dict, bytes).")

                obj.add( payload["name"], r )


        return obj


    def delete(self, obj, jsonPointer=None, payload=None):
        """Delete a Cordra object or part of a Cordra Object"""

        delete_params = {
            jsonPointer: jsonPointer,
            payload: payload
        }

        delete_params = {k:v for k,v in delete_params.items() if v}

        r = self._session.delete( url=self._objects_url(obj.id), params=delete_params )

        return r


    def find(self, query, params, ids=False, jsonFilter=None, full=False):
        """Find a Cordra object by query"""

        params = dict()
        params["query"] = query
        params["full"] = full
        if jsonFilter:
            params["filter"] = str(jsonFilter)
        if ids:
            params["ids"] = True
        r = self._session.get(
                self._objects_url(),
                params=params,
                auth=set_auth(username, password),
                headers=set_headers(token),
                verify=verify,
            )

        return r


def tocordrajson(obj, **kwargs):
    instance_dict = copy.deepcopy( obj.__dict__ )
    instance_dict = {k: v for k, v in instance_dict.items() if v is not None}
    return json.dumps(instance_dict, **kwargs)


class CordraObject(BaseModel):
    type: str
    id: str=None
    related: "CordraObject"=None
    _cordraclient: CordraClient=PrivateAttr()
    _payloads: Dict=PrivateAttr()


    class Config:
        arbitrary_types_allowed = True
        validate_assignment = True
        extra = Extra.allow #Options are Extra.forbid and Extra.allow not T/F
        json_encoders = {
            BaseModel: lambda obj: obj.id,
            # datetime: lambda v: v.timestamp(),
            # timedelta: timedelta_isoformat,
        }

    
    def __init__(self, **initialization):
        super().__init__(**initialization)
        # If an id was passed, pull the object from Cordra
        # if self.id:
        #     self.sync_from_remote()
        # Else, if there is a connection a remote Cordra instance
        # then create the object and obtain an id
        self._payloads = dict()

        if isinstance(self.__private_attributes__["_cordraclient"], CordraClient):
            self.create()

    def json(self):
        return tocordrajson(self)


    # def __setattr__(self, key, val):
    #     if isinstance(val, CordraObject):
    #         val = val.id
            
    #     self.__dict__[key] = val


    # Data property
    def data(self, title):
        if filename:
            return self._payloads[title]

        return self._payloads[title][1]


    # Add data
    def add(self, title, filepath_or_bytes, filename=None):
        """Add an object to this class from filepath or bytes"""
        
        if isinstance(filepath_or_bytes, bytes):
            if filename is None:
                filename = title
            self._payloads[title] = (filename, filepath_or_bytes)

        elif os.path.isfile(filepath_or_bytes):
            if filename is None:
                filename = os.path.basename(filepath_or_bytes)
            with open(filepath_or_bytes, 'rb') as f:
                self._payloads[title] = (filename, f.read())

        else:
            raise OSError("No bytes object identified and File does not exist!")


    def get(self, title, filename=False):
        if filename:
            return self._payloads[title]

        return self._payloads[title][1]


    def rem(self, title):
        return self._payloads.pop(title, None)


    def add_object(self, title, pythonObject):
        # Raise insecure warning
        warnings.warn("""Pickled objects are executed on read and are insecure!""")
        # Pickled object in bytes
        # Python version
        # ObjectType
        raise NotImplementedError("Pickling is insecure and we are still working on this feature.")

    def get_object(self, title):
        # Raise insecure warning
        warnings.warn("""Pickled objects are executed on read and are insecure!""")
        raise NotImplementedError("Pickling is insecure and we are still working on this feature.")


CordraObject.update_forward_refs()