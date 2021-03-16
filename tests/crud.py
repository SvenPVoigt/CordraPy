from cordra import Engine, CordraObject
from io import BytesIO
from PIL import Image
import json

engine = Engine(host="https://localhost:8443/", credentials_file="secretlogin.json", verify=False, params={"full": True})

test = CordraObject(type="Document", awesome="test")
test.hello = "world"

print( "Test JSON object")
print( test.json() )
print( engine.create(test) )

test.add("test.json", json.dumps({"a": "a", "b":"b"}).encode())

print( "\n" )
print( "Test JSON object with JSON payload")
print( test.json() )
print( test._payloads )

print( engine.create(test) )

stream = BytesIO()
A = Image.radial_gradient("L").resize((11,11))
A.save(stream, format="PNG")
test.add("radial.png", stream.getvalue())

print( "\n" )
print( "Test JSON object with Image payload")
print( test.json() )
print( test._payloads )

print( engine.create(test) )