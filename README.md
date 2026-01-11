# YubiHSM Playground

Playground for YubiHSM.

## PKCS#11 GUI

Setup with YubiHSM:
1. Populate `/etc/yubihsm_pkcs11.conf` with `connector = yhusb://`.
2. Run `YUBIHSM_PKCS11_CONF=/etc/yubihsm_pkcs11.conf uv run main.py` inside the `pkcs11-gui` directory.
3. Paste the path to the YubiHSM PKCS#11 library, e.g. `/usr/lib/pkcs11/yubihsm_pkcs11.so`.
4. Enter the PIN. By default, it is prefixed with the 4-digit authentication key id, cf. https://developers.yubico.com/yubihsm-shell/yubihsm-pkcs11.html. For example, when using the authentication token `1` with the default password `password`, the PIN would be `0001password`.
