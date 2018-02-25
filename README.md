# Secrets
Cross-Platform Desktop application to securely store short secrets

## Features

The user remembers one single password overall and the application uses the password to derive a different (cryptographically random) set of symmetric keys for each secret that needs to be protected. Each secret is encrypted and integrity protected using the symmetric keys and stored in the local db. The password and the symmetric keys are never stored anywhere, so only the user can decrypt the secret(s) using the original password. This combines the flexibility of users remembering one single (hopefully strong) password with the cryptographic security of protecting secrets using different symmetric keys. The following algorithms are supported, 

Encryption/Decryption   : AES-256-CBC, AES-256-CTR
HMAC                    : HMAC-SHA-256, HMAC-SHA-512
KDF                     : PBKDF2

The algorithms are configurable and support for other cryptographic algorithms will be added as and when dotnet core adds support.
The application is cross-platform and runs on Windows, Linux and Mac OS X.



## steps to run the program
1. install the dotnet core runtime - https://www.microsoft.com/net/learn/get-started/macos
2. clone the Secrets repository - https://github.com/rohitg15/Secrets.git 
3. cd Secrets
4. dotnet run --project ./Secrets
5. do not delete the db directory. It saves the protected secret files. 


