from cordra import Engine, CordraObject

engine = Engine(host="https://localhost:8443/", credentials_file="secretlogin.json", verify=False)

class Test(CordraObject):
    type: str = "Document"
    hello: str = "world"


t = Test()
print(t.json())
engine.create(t)