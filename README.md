# OpenFIPS201 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project has been commissioned and funded by the Australian Department of Defence, to provide an open source implementation of the card application for the NIST Personal Identity Verification (PIV) standard as specified by [FIPS PUB 201-2](https://en.wikipedia.org/wiki/FIPS_201) and [SP800-73-4](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf). 


**OpenFIPS201 implements the following functionality:**

* A flexible filesystem that can be defined easily without recompilation
* A flexible key store that defines key roles instead of hard-coding which key is used for what function
* It compiles to Javacard 2.2.2 for maximum compatibility (this will be forked to separate 3.0.x and 2.2.x builds)
* Secure personalisation over SCP w/CEnc+CMac using the CHANGE REFERENCE DATA and PUT DATA commands
* The following is out-of-scope at this time:
  * Elliptic Curve Cryptography mechanisms
  * Virtual Contact Interface
  * Secure Messaging (Opacity)
  * Biometric On-Card Comparison (OCC)
  

To get started, please head on over to the [OpenFIPS201 Wiki](https://github.com/makinako/OpenFIPS201/wiki)

The latest binary release is: [OpenFIPS201 v1.0.0-beta6](https://github.com/makinako/OpenFIPS201/releases/tag/v1.0.0-beta6)


**Want to get in touch?**

Contact us at piv@makina.com.au if you want to talk about the project, or just to even say how you're using it!
