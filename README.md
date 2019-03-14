# ECDSA-SM2-Signing-Attack

Attacking ECDSA/SM2 signature.

Objectives:

* Recover private key
* Generate valid signature(s) without private key
* Recover random relationship

Here SM2 is implemented in "crypto/sm/sm2" and SM3 in "crypto/sm/sm3". Please change to your own GM implementation folder.

#### Recover Private Key

* Recover the private key when signing with insure randoms
  Requirement:
  * Random relationship (possible for all `r2 = f(r1)`; here only consider `r2 = a * r1 + b` as an example)
  * Two valid signatures

* Recover the private key when random is leaked
  Requirement:
  * Random number
  * Valid signature on the leaked random

#### Generate valid signature(s) without private key (not considering hash)

* Generate another valid signature based on a given signature (only works for ECDSA)
  Requirement:
  * Valid signatures

* Generate a valid signature with the public key
  Requirement:
  * Public key
  
#### Recover random relationship
* Recover the random relationship of two given signatures
  Requirement:
  * Two valid signatures
  
  
_NOTE: simply combining different attacks will not get the expected result. E.g. `given two signatures -> random relationship -> private key` will not work._ 