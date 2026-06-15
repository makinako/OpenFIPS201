# OpenFIPS201 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> [!WARNING]  
> This is the _unreleased_ version of the OpenFIPS201 v2.0 FIPS applet! It is the code-base that passed the FIPS 140-3 testing, however the release for this applet is subject to final submission from the lab and so until then, consider this a preview to help users understand what has changed in more detail.
> 

**Applet Features:**

- All core PIV crypto operations and mechanisms (RSA sign/transport, ECDSA/ECDH, symmetric, symmetric int/ext/mutual auth) and PIV-SM. RSA4096 included in addition to RSA3072 from the latest SP800-73 version. Supports RSA-CRT and vanilla private keys.
- Biometric OCC only current exception to the above as it created additional difficulties for the FIPS certification due to the third-party MoC library.
- Targets JCRE3.0.5 / GP2.3 but with a platform abstraction layer to easily switch to other cards/JCRE's and make selective use of proprietary vendor libs.
- SCP03 administration with CENC+CMAC enforced.
- Same binary for all users, entirely driven by config with exception of FIPS_APPROVED being a compile constant to lock FIPS constraints in the approved binary.
- Flexible Applet configuration - Ability to define any data or security model via pre-perso script (The applet becomes a PIV token when an NPIVP pre-perso script is used).
- Flexible Data store - Define standard or custom objects with ability to define identifiers, contact/contactless permissions, key roles type-specific attributes.
- Flexible PIN store - Selectively supports some or all of Local, Global, PUK, Pairing with optional 4-16 length, multiple charsets, PIN history, weak-pin prevention, flexible retries, etc.
- Flexible Key store - Define any mandatory, optional and additional keys, including ID, mechanism, key role, usage attributes.
- Optional user-administrable data objects for non-security-related business data (i.e. Store your favourite MRE flavour!).
- `SECURED` applet life-cycle state to lock pre-perso down.
- Operational key injection under SCP03 (and we are now adding SCP03+wrap).
- Status `GET STATUS` and version `GET VERSION` reporting.
- Optional `GET RANDOM` command to return arbitrary random bytes to allow entropy from a FIPS source in any environment.
- Optional `GET CONFIG` to return config, container, key and PIN headers for enumeration in flexible environments.



----
