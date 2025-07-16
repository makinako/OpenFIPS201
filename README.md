# OpenFIPS201 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


| IMPORTANT: This is the _unreleased_ version of the OpenFIPS201 v2.0 FIPS applet! It is the code-base that passed the FIPS 140-3 testing, however the release for this applet is subject to final submission from the lab and so until then, consider this a preview to help users understand what has changed in more detail. |
| ------------------------------------------------------------ |


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



# OpenFIPS201 Java Card Applet — Release Notes v2.0.1-JC304

## 1  General information

|||
|:-------|:-------|
| **Release ID** | v2.0.1-JC304 |
| **Build date** | 2025-07-16 |
| **Git tag / commit** | [ea6e0de](https://github.com/makinako/OpenFIPS201/commit/ea6e0de6e23cdb8fc719bb4534f33f82d6440c5c) |
| **Build Java Card SDK** | 3.0.4 |
| **Build JDK** | 11.0.2 (Oracle - 144d476b6efe) |
| **Target Java Card SDK** | 3.0.4 |
| **Target GlobalPlatform API** | 1.6 (GPCS 2.2.1 / 2.3) |
| **Build Host** | MS-WIN11 64-bit v10.0.19045.6093 |
| **Build Toolchain** | ant-javacard 24.11.19 |
| **Build Flags** | <ul><li>VERSION_MAJOR=2</li><li>VERSION_MINOR=0</li><li>VERSION_REVISION=1</li><li>FIPS_APPROVED=true</li><li>VERSION_DEBUG=false</li><li>DEBUG_FIPS_RUN_ACVP=false</li></ul>|


## 2  Executive summary
This is an update the FIPS code base to the JC304 platform. For now since AES_CMAC_128 is not supported by default in the v3.0.4 JCRE, dependent features are disabled. Also RSA3072 and RSA4096 are temporarily disabled until tested working on a JC304 platform.

 **IMPORTANT**: Even though this build has the FIPS_APPROVED flag set, this is only indicates that the FIPS constraints are applied, and this is **not** a FIPS approved module.

---

## 3  Change log  

- **[OF-328](https://openfips201.atlassian.net/browse/OF-328)** Implement JC304 platform  
- **[OF-329](https://openfips201.atlassian.net/browse/OF-329)** Temporarily disable PIV-SM  (AES_CMAC_128 dep)  
- **[OF-330](https://openfips201.atlassian.net/browse/OF-330)** Temporarily disable Operator integrity check (AES_CMAC_128 dep) 
- **[OF-331](https://openfips201.atlassian.net/browse/OF-331)** P60 cannot handle APDU.sendBytesLong() call with 0-byte length 
- **[OF-332](https://openfips201.atlassian.net/browse/OF-332)** Temporarily disable RSA3072 (P60 default config) 
- **[OF-333](https://openfips201.atlassian.net/browse/OF-333)** Temporarily disable RSA4096 (P60 default config) 

----
