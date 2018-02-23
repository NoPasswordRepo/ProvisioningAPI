This Python project contains several code samples about how to interact with NoPassword services.

**Users Provisioning:**

    A sample code that shows how to interact with NoPassword API to manage users, groups, group members and roles.
    Users provisioning API exchanges JSON encrypted messages. 
    
    In order to start using the API you must:
    - Provide a RSA public an private key in PEM format.
    - Register public key at NoPassword.
    - Set generic API key in config.properties file. Copy key value from NoPassword Admin portal - Keys - Generic API.
    
    A working sample can be found at UsersProvisioningSample.py.