"""Check the CordraClient Class and its functionality. Should be able to fully reproduce the 
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
* Reading all schemas from a remote Cordra instance and turning them into python classes
"""


from cordra import CordraClient, CordraObject
from io import BytesIO
from PIL import Image
import json
import requests

# Connect to the test repository
repository = CordraClient(host="https://localhost:8443/", credentials_file="secretlogin.json", verify=False)




# Test 1 - Check that a python CordraObject matches the remote Cordra Object
test = CordraObject(type="Document", awesome="test") # Create python CordraObject without remote
test.hello = "world"

r = repository.create(test) # Write to Cordra
test.id = str( r["id"] ) # Update the id from None to the id assigned by Cordra

test_remote = repository.read( test.id ) # Read the cordra object and compare to original

assert test.dict() == test_remote.dict(), \
    "Remote and local objects are note the same." # Check equivalence of objects' dicts




# Test 2 - Create python CordraObject with payloads. Check that local and remote payloads are equal
J = {"a": "a", "b":"b"}
test.add("test.json", json.dumps(J).encode()) # Add a json payload as bytes

stream = BytesIO()
A = Image.radial_gradient("L").resize((11,11))
A.save(stream, format="PNG") # Write a png image to bytes object
test.add("radial.png", stream.getvalue()) # Add the png (in bytes) as payload

r = repository.create(test) # Create cordra object with payloads
test.id = str( r["id"] ) # Update the id from None to the id assigned by Cordra

test_remote = repository.read( test.id, getAll=True ) # Read the Object and Payloads

K = json.loads( test_remote.get("test.json").decode('utf-8') ) # Decode payload bytes
assert J==K, "JSON payload was corrupted."

B = test_remote.get("radial.png")
assert stream.getvalue()==B, "Image bytes were corrupted."




# Test 3 - Update an object (Reuse object from Test 2)
test.updateditem = "SendUpdate" # Update the attributes of object
L = {"c": "c", "d":"d"}
test.add("test.json", json.dumps(L).encode()) # Update the JSON payload
print(test.__dict__)
print(test._payloads)
repository.update(test, updatePayloads=False)

test_remote = repository.read( test.id ) # Check that the updated objects are the same
assert test.dict() == test_remote.dict(), "Updated object attributes differ after synced update."

test_remote = repository.read( test.id, getAll=True )
K = json.loads( test_remote.get("test.json").decode('utf-8') )
assert J==K, "JSON payloads differ after synced update."




# Test 4 - Deletion of payloads and properties
## Delete a payload
### Verify payload doesn't exist

## Delete a property of object
### Verify property doesn't exist


# Test 5 - Delete an object
## Delete the object
repository.delete(test)
### Verify the object does not exist
try:
    print( repository.read(test.id) )
except requests.exceptions.HTTPError:
    print("Object deleted successfully")

# Test 6 - Update ACLs
## create user
# guest = 
## create object with ACL that includes created user
## create an engine with the new user credentials
## check that object can be edited by the new user


