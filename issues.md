# Features
* CordraClient class
    * add pytest CRUD tests with running Cordra instance to doctests
    * ACL functionality
      * Set default ACL on Auth
      * ACL validatation. Does updating overwrite the acl correctly?
      * Create ACL tests
    * Authentication through public/private keys
    * Update always updates the whole object. Could simplify with json pointers.
      * Biggest time waste is if metadata is changed and payload is not
      * Highest priority is only updating payloads function
* CordraObject
    * Generate python classes from Cordra schema objects
    * Turn the add function into a data property
    * Add filetypes to the data elements such that requests will add filetype
    as metadata in Cordra
    * Initialize with a created datetime
    * Custom serialization of datetime objects

# Bugs and Potential Bugs
* Identify bugs
* Allowing params in Engine class that shouldn't be default params but specific to auth/create/update/delete operations