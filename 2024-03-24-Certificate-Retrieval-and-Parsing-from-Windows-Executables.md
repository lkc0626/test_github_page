---
title: 'Certificate Retrieval and Parsing from Windows Executables'
date: 2024-03-25
permalink: /posts/2024/03/Certificate-Retrieval-and-Parsing-from-Windows-Executables/
tags:
  - JavaScript
  - code signing
  - code signing PKI
  - digital signature
  - PKCS7
  - x.509 certificates
  - code signing certificates
---

<!-- # Certificate Retrieval and Parsing from Windows Executables  -->

###### Parker Collier - March 24, 2024

Windows executables use a Certificate system similar to those employed by websites and web servers. These are attached to the [Windows Portable Executable](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only) using asn.1 encoding, specifically individual X.509 certificates are bundled into a certificate-chain showing the path of authentication from the application itself to the root CA. These bundles are then appended to the end of the executable. 

These certificates are built off of the [ASN.1](https://en.wikipedia.org/wiki/ASN.1) syntax, a standard interface for defining data structures. More specifically they use the [X.509](https://en.wikipedia.org/wiki/X.509) format, which was created from the Asn.1 syntax. The raw file type for X.509 certificates is DER, the base-64 encoded text based file type is PEM. [Object Identifier tags (OID tags)](http://oid-info.com/index.htm) are numeric decimal values used to define sections of the X.509 format.

I built a website, [https://code-signing.utk.edu/](https://code-signing.utk.edu/)  for the purpose of parsing these certificates from uploaded windows executables and displaying them in a readable format. The website allows for multiple upload methods. Windows Executables or raw DER files can be uploaded via the prompt on the main page. Alternatively text based PEM files can be pasted into the indicated text box.

I use an npm package called [portable-executable-signature](https://www.npmjs.com/package/portable-executable-signature) to extract certificate chains from windows executable. When a file object is uploaded to the site, this script use a try-catch system to check if the uploaded file is an executable with an attached certificate or is a raw DER upload. 

    //grab the filename from the upload
    var filename = document.getElementById("execFile").value
    var pkDER

    //extract the desired filename value
    filename = filename.replace("C:\\fakepath\\", "")

    //get a binary buffer containing the uploaded file data
    const fileBuff = this.result
    const num = Math.floor(Math.random() * 10000);

      if (filename.includes(".exe")){//check for .exe file upload
      filename = filename.replace(".exe", "")
        try {//attempt to extract the certificate from the uploaded executable
          let sig = signatureGet(fileBuff) // function for parsing certificates from .EXE files (portable-executable-signature)
          uploadCert(fileBuff, `${num}-${filename}`, ".exe")
          pkDER = sig.slice(8)
        }catch(error) {//on failure set bad tag for later inspection
          pkDER = "bad"
        }
      }else{//otherwise we are on DER upload and can simply assume the uploaded data is ready for processing
        pkDER = (fileBuff)
      }

This try-catch method will parse certificates properly regardless of file extension names.

Once a certificate has been uploaded to the site, it is parsed using the [pkijs](https://pkijs.org/) and [asn1js](https://www.npmjs.com/package/asn1js) npm packages. Pkijs and its extension asn1js are schema based scripts used to convert raw X.509 data into interactable javascript objects. A similar try-catch system is used to parse the certificate itself, first attempting to treat it as a certificate chain:

    try {//attempted to load binary data into asn1 and pkijs objects, assume the data is an entire windows certificate
        const asn1 = fromBER(pkDER)// function to decode binary DER data into a asn1js object (ans1js)
        const ContentSimpl = new ContentInfo({ schema: asn1.result }); //function to convert asn1.js data into a Content Info scheme (pkijs)
        const SignedSimpl = new SignedData({ schema: ContentSimpl.content }) //function to convert Conto Info Schema into Signed Data schema (pkijs)
        uploadCert(pkDER, `${num}-${filename}`, ".der")

        //walk through all X.509 certificates in the Signed Data object
        for (const cert of SignedSimpl.certificates){

          //create binary data for DER download
          const derBuff = new Buffer.from(cert.toString("base64"), "base64")
         
          //push (certificate, binary) tuple
          certs.push([await makeJSON(cert), derBuff])
        }
      }

Then upon failure, attempts to read the data as a single certificate.

    catch(error){//on error attempt to read a single X.509 certificate
        try{
          const asn1 = fromBER(fileBuff)
          const SignedSimpl = new Certificate({schema: asn1.result}) //instead of reading into Content Info like above, read directly into a Certificate schema
          uploadCert(fileBuff, `${num}-${filename}`, ".der")
          //push (certificate, binary) tuple
          certs.push([await makeJSON(SignedSimpl), fileBuff])
          //set download data for individual certificate
          pkDER = fileBuff
       
        }catch(error) {//if both of the above try statements fail, set bad tag for later inspection
          pkDER = "bad"
        }
      }

Once the certificate is loaded into a JavaScript object, each X.509 section is parsed from the object and rendered as an interactable drop down tree via custom javascript. All common OID tags are translated by the website into their readable formats. All displayed certificates have the option to be downloaded in their default DER file format, or copied to the user's clipboard in a PEM format. Certificates can be downloaded individually or as a whole chain.

The website itself is written using html/css/javascript, code files and npm packages are built and bundled for development using [webpack, a popular](https://webpack.js.org/) asset bundling tool. Various tools from the [AWS suite](https://aws.amazon.com/) are used to host the site. All functionality related to certificate parsing and interaction is performed client side. An alternative goal for this project is to construct a significant dataset of real certificate files used in the wild. For this purpose, all certificates uploaded to the website are automatically backed up to an AWS bucket using AWS cloud tools. No other user information outside of normal AWS website analytics is stored.
