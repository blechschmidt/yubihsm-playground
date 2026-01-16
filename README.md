# YubiHSM Playground

Playground for YubiHSM. This is not a production-grade project. It mainly serves as personal note.

## PKCS#11 GUI

Setup with YubiHSM:
1. Populate `/etc/yubihsm_pkcs11.conf` with `connector = yhusb://`.
2. Run `YUBIHSM_PKCS11_CONF=/etc/yubihsm_pkcs11.conf uv run main.py` inside the `pkcs11-gui` directory.
3. Paste the path to the YubiHSM PKCS#11 library, e.g. `/usr/lib/pkcs11/yubihsm_pkcs11.so`.
4. Enter the PIN. By default, it is prefixed with the 4-digit authentication key id, cf. https://developers.yubico.com/yubihsm-shell/yubihsm-pkcs11.html. For example, when using the authentication token `1` with the default password `password`, the PIN would be `0001password`.

## Goals
1. Verification of HSM genuineness. Solved, cf. `./verify-authenticity`.
2. Public auditability: https://gist.github.com/karalabe/fb7ac43f3899f511b5547279c036bf4e
3. PKI setup, cf. runbook below.
4. Key backup.

## Runbooks

### Generating a CA and a certificate

Description of how to generate a CA whose private key lives inside the HSM and a certificate whose private key lives outside the HSM.

1. Export the relevant variables for `openssl` PKCS#11 usage.
    ```sh
    export PKCS11_PROVIDER_MODULE=/usr/lib/pkcs11/yubihsm_pkcs11.so
    export YUBIHSM_PKCS11_CONF=/etc/yubihsm_pkcs11.conf
    ```


1. Generate CA key:
    ```sh
    pkcs11-tool --module /usr/lib/pkcs11/yubihsm_pkcs11.so --login --pin 0001password --keypairgen --key-type rsa:2048 --label "ca_key" --usage-sign
    ```

2. Generate self-signed CA cert:
    ```sh
    openssl req -new -x509 \
    -key 'pkcs11:object=ca_key;type=private' \
    -out ca.crt \
    -days 3650 \
    -sha256 \
    -subj "/C=US/O=Example Org/CN=Example Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
    ```

3. Generate server key:
    ```sh
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out server.key
    ```

4. Generate the CSR:
    ```sh
    openssl req -new \
    -key server.key \
    -out server.csr \
    -subj "/C=US/ST=State/L=City/O=ExampleOrg/OU=IT/CN=example.com" \
    -addext "subjectAltName=DNS:example.com,DNS:www.example.com"
    ```

5. Sign the CSR:
    ```sh
    openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey "pkcs11:object=ca_key;type=private" \
    -CAcreateserial \
    -out server.crt \
    -days 365 \
    -copy_extensions copy
    ```
