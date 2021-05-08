# CordraClient Implementation
The CordraClient replaces the previous Object class. Its purpose is not to represent the cordra objects but to support CRUD operations with a running Cordra instance. In addition to CRUD, the CordraClient allows access to the full functionality of the Cordra REST API. This includes:

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

All of these features are tested in the `tests/CordraClient_tests.py`.

# CordraObject Implementation