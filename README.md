# OpenFIPS201 [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project has been commissioned and funded by the Australian Department of Defence, to provide an open source implementation of the card application for the NIST Personal Identity Verification (PIV) standard as specified by [NIST FIPS PUB 201-2](https://en.wikipedia.org/wiki/FIPS_201) and [NIST SP 800-73-4](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf). 

**OpenFIPS201 implements the following functionality:**

* A flexible filesystem that can be defined easily without recompilation
* A flexible key store that defines key roles instead of hard-coding which key is used for what function
* It compiles to Javacard 3.0.4 as a minimum
* Secure personalisation over SCP w/CENC+CMAC using the CHANGE REFERENCE DATA and PUT DATA commands
* The following is out-of-scope at this time:
  * Virtual Contact Interface
  * Secure Messaging (Opacity)
  * Biometric On-Card Comparison (OCC)

To get started, please head on over to the [OpenFIPS201 Wiki](https://openfips201.atlassian.net/wiki/spaces/OD/overview)
The latest binary release is: [OpenFIPS201 v1.10.0](#ref)

**Want to get in touch?**

Contact us at piv@makina.com.au if you want to talk about the project, or just to even say how you're using it!

To contact the author directly, email kim@makina.com.au

**This project makes use of the following Open Source tools:**

* [Apache Ant](https://ant.apache.org/) by the [Apache Foundation](https://www.apache.org/)
* [Ant-JavaCard](https://github.com/martinpaljak/ant-javacard) by [Martin Paljak](https://github.com/martinpaljak)
* [Google Java Format](https://github.com/google/google-java-format) by [Google](https://github.com/google)

----



### UPDATE 4th April 2022 - OpenFIPS201 v1.10.0 Release

The latest revision of OpenFIPS201 is ready! Here are a few features and enhancements that have been added:

#### Documentation

* Documentation relating to OpenFIPS201 has now been moved [here](https://openfips201.atlassian.net/wiki/spaces/OD/overview) to a public Confluence instance, as the docs were outgrowing the GitHub wiki. 
* [Discussions](https://github.com/makinako/OpenFIPS201/discussions) has now been enabled, we welcome any feedback you have or let us know how you're using OpenFIPS201!

#### Dynamic Configuration

All `FEATURE` compilation constants are now gone and been replaced with a more extensive set of configuration registers for controlling aspects of applet behaviour. This means there is no longer a need to modify or build from source code in order to configure it.

All configuration elements can be updated either individually, or batched into a single command (using OPTIONAL ASN.1 elements). If you choose not to update the configuration, you can just use the default values that have all been defined to adhere to PIV, or if PIV doesn't specify something then sensible default values have been used.

#### Pre-Personalisation Interface

The PUT DATA ADMIN command has changed a bit due to dynamic configuration. The following BER-TLV structures are defined:

* Create Data Object
* Delete Data Object (Defined but not implemented)
* Create Key Command
* Delete Key (Defined but not implemented)
* Update Configuration
* Legacy Operation

Your current pre-perso will still work via the `Legacy Operation`, but you will not be able to take advantage of some of the extended features, notably dynamic configuration. We encourage you to migrate over to the new commands, which have been kept as similar as possible to ease the transition.

#### Bulk Pre-Personalisation

You can combine any number of the above pre-perso commands into the same APDU to reduce the command overheads of sending so many of them!

The command is identical to the normal `PUT DATA ADMIN` format, with the exception that you have an outer BER-TLV tag that contains a SEQUENCE OF individual commands.

You can also mix and match different kinds of updates in one (i.e. Keys, Data Objects and Config).

#### PIN Enhancements

The applet supports a number of additional useful enhancements to PIN functionality:

* PIN Extended Length - You can define PIN lengths up to 16 digits in dynamic configuration
* PIN Character Set - You can define PIN format requirements as either `numeric`, `alpha numeric`, `alpha numeric (case insensitive)` or `raw` (any byte value)
* PIN History - You can configure the applet to remember up to the last 12 PIN values that were changed and prevent the user from re-using them.
* PIN Complexity Rules - Two basic 'weak PIN' prevention rules have been added as optional parameters:
  * Sequence Rule - Allows you to prevent more than `[n]` consecutive digits from being used (for example, 123456).
  * Distinct Rule - Allows you to prevent more than [n] instances of the same character being used (for example, 111111).
* PUK Retry Limits - PUK retries can now be defined in the same way PIN retries are (including separate counters for the Contact and Contactless interface). If the PUK is locked, it can only be unlocked by an administrative role over SCP03.

<u>PIV Impacts:</u>

- Setting the PIN Extended Length feature above 8 or below 6 will cause the padding/length to no longer comply with SP 800-73.
- Setting the PIN Character Set to anything other than `numeric` will not work with any middleware that enforces numeric-only digits. 
- PIN History and Complexity Rules should be transparent and simply result in an error condition that should be handled by PIV middleware / clients.

#### Dynamic Admin Keys

For each data object and asymmetric key, you can now optionally define which symmetric key is responsible for managing it. This gives you the capacity to give write / key generation access to targeted objects. This feature is optional and if you do not specify an admin key, objects will default to the`9B` key.

<u>PIV Impact</u>: PIV defaults to the `9B` key as the administrative key, so to maintain compatibility, simply define this key or don't specify the key.

#### User Manageable Data Objects

For asymmetric keys and data objects, it is possible to now add the `User Admin` access mode privilege. If this is set, the data object can be written to, or the key generated as long as the access conditions for that card have been met. This can be separated for contact / contactless and the special 'always' access mode may not be paired with this.

This has been included to permit the possibility of lower security applications whereby it is useful for regularly-changing operational data to be managed on the card without the requirement for administrative keys. Of course if the thought of this horrifies you, do nothing to your pre-perso scripts and the functionality will stay disabled.

#### Optional Cryptographic Mechanisms

The applet now attempts to instantiate all the required cryptographic mechanisms, but if there are any that it can't this now only results in those corresponding mechanisms being disabled, not prevention of the entire applet install.

<u>PIV Impact:</u> None, provided the card is able to support at least one of the asymmetric key pair types.


#### Other

* The GlobalPlatform library now targets GP 2.2.1 instead of GP 2.1.1. This should not pose a problem for JC 3.0.4+ cards.
* The `Admin` key attribute has now been deprecated as it replaced by the `adminKey` option
* A `Permit Mutual` key attribute has been added for symmetric keys so it needs to be explicitly enabled. For legacy operations this attribute is automatically applied to maintain compatibility.
* The discovery object is generated at run-time instead of applet compilation now, so you can change configuration parameters and it will reflect correctly.
* `FEATURE_STRICT_APDU_CHAINING` has been removed as ISO7816 is pretty clear that you should be able to interrupt chained commands without an error. 
* `FEATURE_DISCOVERY_OBJECT_DEFAULT` has been removed now that the discovery object generates every call.
* `FEATURE_PIV_TEST_VECTORS` has been removed as it's usefulness reduced with ECC support and FIPS 140 doesn't like test values.
* The `Options.restrictContactlessGlobal`configuration parameter has been added, which will make the applet non-selectable over the contactless interface.
* The `Options.restrictContactlessAdmin` configuration parameter has been added, which prevents SCP03 administration over contactless.
* The `Options.restrictSingleKey` configuration parameter has been added, which will prevent the applet from allowing the same key to be defined with multiple mechanisms.
* `GET STATUS` and `GET VERSION` are improved (more additions and improvements will follow in the coming months, but compatibility with the current response bytes will be maintained so don't hard-code length requirements into your code!).
* Lots of other background changes, code review changes, etc.



----



### UPDATE - 25th July 2021

The applet has been updated (and will continue to be) over the next few months for accreditation.
Below is a summary of changes, with wiki updates to follow shortly:

- General review for FIPS 140-3 + Static analysis + all General Authenticate cases
- Splitting of General Authenticate, which was getting too complex.
- Changes to Key Roles and addition of Key Attributes (compatibility break for pre-perso!)
- Beginning of support for multi-byte data object id's (pre-perso only, not breaking compatibility yet)
- Addition of GET VERSION command to get major/minor/revision/debug status
- Addition of GET STATUS command (more to be added to this)
- Removal of FEATURE_PIV_TEST_VECTORS and all test data (FIPS 140-3 doesn't permit it)
- SSP Deletion - Key and data objects can now be properly zeroised/cleared
- Numerous minor fixes and changes (none breaking the PIV interoperability)
- Namespace change to all-lowercase

Note that because of [issue #29](https://github.com/makinako/OpenFIPS201/issues/29) there is a minor breaking change to the pre-personalisation interface. Details are in the comments and will be updated in the documentation. Feedback is still sought on whether this can be improved as things are flexible up until validation starts.

----



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

----



### **<u>UPDATE - 27th August 2020</u>**

Thanks largely to the efforts of [@dmercer-google](https://github.com/dmercer-google) we now have support for Elliptic Curve! You can now generate key objects with ECC256 (#11) and ECC384 (#14) mechanisms and make use of them in General Authenticate for authentication, signing and key establishment. VCI / SM is not yet included in this, but watch this space. Thanks Dave!

----




### **<u>UPDATE - 22nd July 2020</u>**

OpenFIPS201 has attempted to maintain compatibility with Javacard 2.2.x, however it is clear that there are a number of very good reasons to move away from it in the context of the PIV standard:

* There are a number of cryptographic primitives that are not supported by JC22, especially in the Elliptic Curve domain. This makes it impossible to fully implement SP800-73-4. 
* The PIV requirement to format signature input blocks off-card, which is not supported by JC22 resulted in the need to implement a hack to encrypt using the private key. Moving to JC30 will allow the use of Signature with 'signPreComputedHash()' and 'setInitialDigest', which are both specifically intended for off-card signature block formatting.
* JC22 does not support the 'Applet.reselectingApplet()' feature, which again is a breaking point for PIV. NIST have indicated they will permit certification exceptions to support JC22 cards, however this hasn't been tested to our knowledge.

Going forward, OpenFIPS201 will target Javacard SDK 3.0.4 as a minimum. To continue to support Javacard 2.2.x we have added a new repository [OpenFIPS201-jc22](https://github.com/makinako/OpenFIPS201-jc22), which will serve as the compatibility release going forward.

----
