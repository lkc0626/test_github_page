---
title: 'Retrieving certificates from Certificates Transparency (CT)'
date: 2020-07-09
tags:
 - Certificates
 - Certificate Transparency
 - CT
---

Researchers who are working on TLS may want to collect certificates for their research. The basic approach is to directly access websites and download its certificates. But sometimes, the websites they want to access can be no longer available due to various reasons.
One of the alternative ways is to utilize Certificate Transparency (CT) that logs TLS certificates as soon as the certificates are issued by Certificates Authorities (CAs). This indicates that all TLS certificates used in the wild are logged in CT logs. If you want to know about CT, please visit [Certificate Transparency: a bird's-eye view](https://emilymstark.com/2020/07/20/certificate-transparency-a-birds-eye-view.html).


According to the [Certificate Transparency RFC](https://tools.ietf.org/html/rfc6962#section-4.6), you can use this API, `https://<log server>/ct/v1/get-entries,` to download certificates from CT. This API requires two parameters, `start` and `end;` `start` is the index of first entry to retrieve and `end` is the index of last entry to retrieve from a CT. For example, `https://<log server>/ct/v1/get-entries?start=0&end=32.` Unfortunately, CT does not return all certificates that you want. In other words, even though you want to download 1,000 certificates at once, the CT returns only the maxmum number of entries per a query, For example, Rocketeer CT returns only 32 certificates regardless of what you request to the CT. This is based on the RFC, "Logs MAY honor requests where 0 <= "start" < "tree_size" and "end" >= "tree_size" by returning a partial response covering only the valid entries in the specified range." But I found that some CT returns a random number of certificates that is obviously less than the maximumb tree size though. For example, `Rocketeer` sometimes returns just one certificate when I request 32 certificates. Moreover, also that some CTs has the maximum requests you can send at once; for example. I don't know the exact number, but it has the maximum request and if you request more than that number, you will be given the `HTTP 429 Too Many Requests` error code. So, typically, I request around 20 requests at once.

CT logs return a json message that contains an array of certificates. Each item in the array consists of leaf_input and extra_data. `leaf_input` is the base64-encoded MerkleTreeLeaf structure (including a TLS certificate) and `extra_data` has the chain of the TLS certificate. I utilize [the construct library](https://pypi.org/project/construct/) to parse the data structure of the leaf_input and extra_data as follows: this code was referenced from [Axeman](https://github.com/CaliDog/Axeman/blob/master/axeman/certlib.py).

```
from construct import Struct, Byte, Int64ub, Int16ub, GreedyBytes, Enum, Int24ub, Bytes, GreedyRange, Terminated, this

MerkleTreeHeader = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / GreedyBytes
)
Certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CertificateChain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(Certificate),
)
```

Axeman is a good tool for retreiving TLS certificates from CT logs; however, it is not a perfect tool for me. I attempted to create another tool with the same features, but more features that I needed are added. My new tool is called AdzeMan and its source code is available at https://github.com/doowon/AdzeMan/. More features are describe in [README.md](https://github.com/doowon/AdzeMan/blob/master/README.md). For example, Axeman uses the old crypto library (pyOpenSSL) so that I changed it to cryptography.io as the old crypto library recommends to use the cryptography,io library.

