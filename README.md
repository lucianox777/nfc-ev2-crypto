# NTAG424 EV2/LRP cryptography example

* `AuthenticateEV2` - perform authentication with PICC;
* `CryptoComm` - sign/encrypt APDUs and validate responses;
* `LRP` - perform CTR mode encryption/decryption or CMACing with Leakage Resilient Primitive.

This code was written according to the publicly available application note *AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints"*.

**Pull requests welcome.**

*Note: NTAG — is a trademark of NXP B.V.*

## Usage
### EV2
Please refer to `test_ev2.py` and cross-check it with the application notes. There are also some docstrings in the `ev2.py` file.

* `AuthenticateEV2` - helper for performing `AuthenticateEV2First` handshake with PICC:
  * `init` - generate the initial C-APDU to start authentication;
  * `part1` - generate a response to first R-APDU from PICC;
  * `part2` - verify second R-APDU from PICC, initialize authenticated session;
* `CryptoComm` - a class which represents "authenticated session":
  * `wrap_cmd` - construct C-APDU in given `CommMode`, convenience wrapper;
  * `unwrap_res` - parse R-APDU in given `CommMode`, convenience wrapper;
  * `sign_apdu` - convert `CommMode.PLAIN` C-APDU into `CommMode.MAC`;
  * `encrypt_apdu` - convert `CommMode.PLAIN` C-APDU into `CommMode.FULL`;
  * `parse_response` - parse R-APDU and verify it's MAC signature (`CommMode.MAC` response);
  * `decrypt_response` - decrypt the response data parsed by `validate_response` (`CommMode.FULL` response);

### LRP

LRICB Encryption (LRICBEnc) and decryption (LRICBDec):
```python
from lrp import LRP

import binascii

# the original key
key = binascii.unhexlify("E0C4935FF0C254CD2CEF8FDDC32460CF")
# plaintext data to encrypt
pt = binascii.unhexlify("012D7F1653CAF6503C6AB0C1010E8CB0")
# also sometimes called "counter"
iv = binascii.unhexlify("C3315DBF")

# encrypt plaintext
lrp = LRP(key, 0, iv, pad=True)
ct = lrp.encrypt(pt)

# decrypt the stuff back
lrp = LRP(key, 0, iv, pad=True)
pt = lrp.decrypt(ct)
```

MACing (LRP-CMAC/CMAC_LRP):
```python
from lrp import LRP

import binascii

key = binascii.unhexlify("8195088CE6C393708EBBE6C7914ECB0B")
lrp = LRP(key, 0, b"\x00" * 16, pad=True)
mac = lrp.cmac(binascii.unhexlify("BBD5B85772C7"))
```

Decrypt SDM PICCData and validate CMAC:
See [test_lrp_sdm.py](https://github.com/icedevml/ntag424-ev2-crypto/blob/master/test_lrp_sdm.py) for an example.
