# OpenFIPS201 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### **<u>UPDATE - 27th August 2020</u>**
Thanks largely to the efforts of [@dmercer-google](https://github.com/dmercer-google) we now have support for Elliptic Curve! You can now generate key objects with ECC256 (#11) and ECC384 (#14) mechanisms and make use of them in General Authenticate for authentication, signing and key establishment. VCI / SM is not yet included in this, but watch this space. Thanks Dave!


### **<u>UPDATE - 22nd July 2020</u>**

OpenFIPS201 has attempted to maintain compatibility with Javacard 2.2.x, however it is clear that there are a number of very good reasons to move away from it in the context of the PIV standard:
* There are a number of cryptographic primitives that are not supported by JC22, especially in the Elliptic Curve domain. This makes it impossible to fully implement SP800-73-4. 
* The PIV requirement to format signature input blocks off-card, which is not supported by JC22 resulted in the need to implement a hack to encrypt using the private key. Moving to JC30 will allow the use of Signature with 'signPreComputedHash()' and 'setInitialDigest', which are both specifically intended for off-card signature block formatting.
* JC22 does not support the 'Applet.reselectingApplet()' feature, which again is a breaking point for PIV. NIST have indicated they will permit certification exceptions to support JC22 cards, however this hasn't been tested to our knowledge.

Going forward, OpenFIPS201 will target Javacard SDK 3.0.4 as a minimum. To continue to support Javacard 2.2.x we have added a new repository [OpenFIPS201-jc22](https://github.com/makinako/OpenFIPS201-jc22), which will serve as the compatibility release going forward.



This project has been commissioned and funded by the Australian Department of Defence, to provide an open source implementation of the card application for the NIST Personal Identity Verification (PIV) standard as specified by [FIPS PUB 201-2](https://en.wikipedia.org/wiki/FIPS_201) and [SP800-73-4](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf). 

**OpenFIPS201 implements the following functionality:**

* A flexible filesystem that can be defined easily without recompilation
* A flexible key store that defines key roles instead of hard-coding which key is used for what function
* It compiles to Javacard 3.0.4 as a minimum
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

To contact the author directly, email kim@makina.com.au
