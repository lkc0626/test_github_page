---
title: 'How to extract a digital signature from a signed PE file in Go '
date: 2019-05-14
permalink: /posts/2019/05/blog-post-1/
tags:
  - go
  - code signing
  - code signing PKI
  - digital signature
  - PKCS7
  - x.509 certificates
  - code signing certificates
---

<!-- # How to extract a digital signature from a signed PE file in Go  -->

Code signing is a mechanism to help establish the authenticity and integrity of binary programs. In particular, `Authenticode` is a standard code signing technology in the Windows platforms. Unlike the Web PKI (i.e., TLS) where TLS certificates are sent along with the TLS handshake messages, in Authenticode, code signing certificates are bundled inside signed PE (Portable Executable) files. More specifically, the code signing certificates are included in Public-Key Cryptography Standards (PKCS) #7 `SignedData`.

In this blog post, I explain how to locate a PKCS #7 `SignedData` that includes x509 v3 code signing certificates.

To extract a PKCS #7 `SignedData` from a signed PE file, two information are required: 1) [Optional Header](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#optional-header-data-directories-image-only) and 2) [Attribute Certificate Table](https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#the-attribute-certificate-table-image-only). The attribute certificate table (ACT) contains a PKCS #7 `SignedData`, whose virtual address and size are specified at the fifth  item of the `Data Directories` array.

In Go, to parse a signed PE file, `debug/pe` library is required. And you find the virtual address and size in the fifth items of the  `DataDirectories` field of `OptionalHeader` ; or you can use `IMAGE_DIRECTORY_ENTRY_SECURITY` of the `IMAGE_DIRECTORY_ENTRY` constants.

The Attribute Certificate Table (ACT) starts the four fields; `dwLength`, `wRevision`, `wCertificateType`, and `bCertificate`. Note that these are little endians. 

- dwLength: the size of the certificate entry (4 bytes)
- wRevision: Certificate version number (2 bytes)
- wCertificateType: Type of content in bCertificate (2bytes)
- bCertificate: A PKCS#7 SignedData that contains code signing certificates (in DER)

To obtain the `SignedData` , you need to access the virtual address + 8 (bytes) of your signed PE file. And you can open the PKCS #7 file with the following command. 

    openssl pkcs7 -in filename -inform der -print

My Go code is available at [https://github.com/doowon/sigtool](https://github.com/doowon/sigtool)
