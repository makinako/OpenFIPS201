# OpenFIPS201 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### **<u>UPDATE - 23th April 2021</u>**
Things have been a bit quiet here, but behind the scenes we are in the process of preparing OpenFIPS201 for CMVP / FIPS 140-3 accreditation! 

This is a very steep learning curve, but out of the process is coming a number of changes that will need to be made to the applet in order to comply with direct requirements or smooth the way through the process. In the next few weeks, I'll be adding these to the issues register to open up the changes to discussion, as some of the changes will impact pre-personalisation and configuration (whilst of course maintaining compatibility with the actual PIV spec).

The (somewhat simplified) phases of accreditation are:
- **Feature Completion** - We are now implementing Secure Messaging, Pairing Code and VCI functionality. This will nearly complete all optional features of the PIV specification, with the notable exception of Biometric On-Card Comparison (OCC). The aim is to have as much as we can in, to avoid the need for re-validation.
- **CMVP Research** - In parallel, we are in the process of understanding the CMVP/FIPS requirements, contacting labs and producing an internally generated gap analysis. 
- **Design, Documentation and Testing** - There are specific documentary requirements for FIPS 140-3, some of which we won't know until we engage the lab.
- **Pre-Validation** - This a workshop, undertaken with our chosen lab to gain an external view of 
- **Validation** - This is the main process where the lab performs the assessment, code review, etc and together with us produces the Security Policy document, which will ultimately be published on the NIST CMVP web site.
- **Submission** - Once everything is in place and the lab has produced all the required documentary evidence, their report is formally submitted to NIST and we join the queue to become a validated product.
- **Approval** - We are assigned a certificate from NIST and we pop the champagne.

One additional aspect, because this is a PIV implementation is that we will also need to undergo NPIVP accreditation. This is effectively an interoperability and functional compliance test rather than security and as I understand it is largely about passing the PIV Test Runner test suite.

If you have any specific questions or issues, please raise them on the issues list or contact us at piv@makina.com.au.


### **<u>UPDATE - 27th August 2020</u>**
Thanks largely to the efforts of [@dmercer-google](https://github.com/dmercer-google) we now have support for Elliptic Curve! You can now generate key objects with ECC256 (#11) and ECC384 (#14) mechanisms and make use of them in General Authenticate for authentication, signing and key establishment. VCI / SM is not yet included in this, but watch this space. Thanks Dave!


### **<u>UPDATE - 22nd July 2020</u>**

OpenFIPS201 has attempted to maintain compatibility with Javacard 2.2.x, however it is clear that there are a number of very good reasons to move away from it in the context of the PIV standard:
* There are a number of cryptographic primitives that are not supported by JC22, especially in the Elliptic Curve domain. This makes it impossible to fully implement SP800-73-4. 
* The PIV requirement to format signature input blocks off-card, which is not supported by JC22 resulted in the need to implement a hack to encrypt using the private key. Moving to JC30 will allow the use of Signature with 'signPreComputedHash()' and 'setInitialDigest', which are both specifically intended for off-card signature block formatting.
* JC22 does not support the 'Applet.reselectingApplet()' feature, which again is a breaking point for PIV. NIST have indicated they will permit certification exceptions to support JC22 cards, however this hasn't been tested to our knowledge.

Going forward, OpenFIPS201 will target Javacard SDK 3.0.4 as a minimum. To continue to support Javacard 2.2.x we have added a new repository [OpenFIPS201-jc22](https://github.com/makinako/OpenFIPS201-jc22), which will serve as the compatibility release going forward.

---

# OpenFIPS201

This project has been commissioned and funded by the Australian Department of Defence, to provide an open source implementation of the card application for the NIST Personal Identity Verification (PIV) standard as specified by [FIPS PUB 201-2](https://en.wikipedia.org/wiki/FIPS_201) and [SP800-73-4](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf). 

**OpenFIPS201 implements the following functionality:**

* A flexible filesystem that can be defined easily without recompilation
* A flexible key store that defines key roles instead of hard-coding which key is used for what function
* It compiles to Javacard 3.0.4 as a minimum
* Secure personalisation over SCP w/CEnc+CMac using the CHANGE REFERENCE DATA and PUT DATA commands
* The following is out-of-scope at this time:
  * Virtual Contact Interface
  * Secure Messaging (Opacity)
  * Biometric On-Card Comparison (OCC)
  

To get started, please head on over to the [OpenFIPS201 Wiki](https://github.com/makinako/OpenFIPS201/wiki)

The latest binary release is: [OpenFIPS201 v1.0.0-beta6](https://github.com/makinako/OpenFIPS201/releases/tag/v1.0.0-beta6)


**Want to get in touch?**

Contact us at piv@makina.com.au if you want to talk about the project, or just to even say how you're using it!

To contact the author directly, email kim@makina.com.au
