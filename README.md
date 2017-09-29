
# OpenFIPS201 ![License](https://img.shields.io/github/license/simpeg/simpeg.svg)

## Why does this project exist?
This project has been commissioned and funded by the Australian Department of Defence, to provide an open source implementation of the card application for the NIST Personal Identity Verification (PIV) standard as specified by [FIPS PUB 201-2](https://en.wikipedia.org/wiki/FIPS_201) and [SP800-73-4](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf). 

## What are the project goals?

This project aims to be a straight-forward reference implementation of the card application as specified in NIST SP800-73-4. 

* To serve as a commonly shared reference between departments and organisations that wish to interoperate using FIPS-201 for logical and physical access control, both within the context of government departments and the industry at large (i.e. CIV).
* To provide a production quality implementation that can be openly reviewed by the industry in keeping with [Kerckoffs' Principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle).
* To provide a common solution to the gaps in the PIV standard, particularly with regards to card management functions and personalisation
* To potentially provide the basis for formal FIPS201 token certification


## What is FIPS PUB 201-2
Straight from the horses mouth:
>This Standard specifies the architecture and technical requirements for a common identification standard
for Federal employees and contractors. The overall goal is to achieve appropriate security assurance for
multiple applications by efficiently verifying the claimed identity of individuals seeking physical access
to Federally controlled government facilities and logical access to government information systems.

While FIPS PUB 201-2 lays out the overall architecture, requirements and procedures, it is more of an umbrella specification. The detailed technical specifications are described in a number of other documents, the most important of these is [NIST SP800-73-4](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf).
This document defines the data model, card application, security and off-card interface (middleware). 

This project implements the PIV Card Application portion of this document.

## What is the PIV Card Application?
The PIV Card Application provides a number of features:
* It contains a file system that allows reading and writing of a number of files (or Data Objects). It controls access to each Data Object using access control conditions, which require some form of authentication by either the cardholder or the Card Management System.
* It provides a number of authentication mechanisms utilising PIN's, symmetric and asymmetric (PKI) algorithms to authenticate the off-card entity
* It allows digital signatures to be generated and also participates in key establishment mechanisms (encryption)
* It provides a means to generate asymmetric keys on-card to provide high assurance, especially where digital signatures are involved

## Getting Started
* [[I want to use OpenFIPS201 in my environment|Usage]]
* [[I am a developer and want to get coding!|Development]]
* [[I want to learn more about Personal Identity Verification|Resources]]
* [[I want to see a list of tasks, bugs, ideas, etc|Project]]
* [[Frequently Asked Questions|FAQ]]

