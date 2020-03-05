# micropython-fido2

This project is an implementation of the [FOD2](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) and [U2F](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-bt-protocol-v1.2-ps-20170411.htmlhttps://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-bt-protocol-v1.2-ps-20170411.html) standards in [micropython](https://micropython.org/) in less than 2000 lines of python code.

The software has been successfully testet on a [Pyboard D-series](https://pybd.io/hw/pybd_sfxw.html).

It uses the HID interface for communication.


# Security

**Warning:** This implemetation is not resisdant to side channel attacks like timing attacks.


# License

[MIT](https://opensource.org/licenses/MIT)


# Testing
For testing clone [fido2-test](https://github.com/pmvr/fido2-tests) and execute
