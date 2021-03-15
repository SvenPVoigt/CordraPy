import requests
import os
import sys
import json

if __name__=="__main__":
    with open( sys.argv[1] ) as loginfile:
        login = json.load(loginfile)


    # First run auth and get token
    data = {"grant_type":"password"}
    data.update(login)

    r = requests.post(
        "https://localhost:8443/auth/token",
        data=data,
        verify=False
    )

    assert r.ok

    headers = {
        "Authorization": "Bearer "+r.json()["access_token"],
        "Content-Type": "application/json"
    }

    r = requests.post(
        "https://localhost:8443/objects/",
        params={"type": "Document"},
        data=json.dumps( {"hello": "world"} ),
        headers=headers,
        verify=False
    )

    assert r.ok