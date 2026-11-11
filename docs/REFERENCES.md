# 📚 المصادر والمراجع

## المعايير الأساسية (Standards)
1. **RFC 7748** — A. Langley, M. Hamburg, S. Turner, *Elliptic Curves for Security* (X25519), IETF, 2016.
   https://www.rfc-editor.org/rfc/rfc7748
2. **RFC 8032** — S. Josefsson, I. Liusvaara, *Edwards-Curve Digital Signature Algorithm (EdDSA)* (Ed25519), IETF, 2017.
   https://www.rfc-editor.org/rfc/rfc8032
3. **RFC 5869** — H. Krawczyk, P. Eronen, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, IETF, 2010.
   https://www.rfc-editor.org/rfc/rfc5869
4. **NIST SP 800-38D** — M. Dworkin, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, 2007.
   https://csrc.nist.gov/pubs/sp/800/38/d/final
5. **FIPS 197** — *Advanced Encryption Standard (AES)*, NIST.
   https://csrc.nist.gov/pubs/fips/197/final
6. **FIPS 180-4** — *Secure Hash Standard (SHS)* (SHA-256), NIST.
   https://csrc.nist.gov/pubs/fips/180-4/upd1/final
7. **RFC 2104** — *HMAC: Keyed-Hashing for Message Authentication*.
   https://www.rfc-editor.org/rfc/rfc2104
8. **RFC 8446** — E. Rescorla, *The Transport Layer Security (TLS) Protocol Version 1.3*, 2018. (مصافحة ECDHE، ربط الـ transcript، key schedule)
   https://www.rfc-editor.org/rfc/rfc8446
9. **RFC 5116** — D. McGrew, *An Interface and Algorithms for Authenticated Encryption* (AEAD، بنية الـ nonce).
   https://www.rfc-editor.org/rfc/rfc5116
10. **NIST SP 800-56A Rev.3** — *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*.
    https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
11. **NIST SP 800-57 Part 1 Rev.5** — *Recommendation for Key Management* (أطوال المفاتيح ومستويات الأمان).
    https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final

## الأبحاث والتصاميم المرجعية
12. D. J. Bernstein, *Curve25519: new Diffie-Hellman speed records*, PKC 2006. https://cr.yp.to/ecdh.html
13. D. J. Bernstein et al., *High-speed high-security signatures* (Ed25519), CHES 2011. https://ed25519.cr.yp.to/
14. H. Krawczyk, *Cryptographic Extraction and Key Derivation: The HKDF Scheme*, CRYPTO 2010. https://eprint.iacr.org/2010/264
15. D. McGrew, J. Viega, *The Galois/Counter Mode of Operation (GCM)*, 2004.
16. T. Perrin, *The Noise Protocol Framework*. https://noiseprotocol.org/noise.html
17. Signal, *The X3DH Key Agreement Protocol* and *Safety Numbers*. https://signal.org/docs/
18. J. A. Donenfeld, *WireGuard: Next Generation Kernel Network Tunnel*, NDSS 2017. https://www.wireguard.com/papers/wireguard.pdf
19. S. Vaudenay, *Secure Communications over Insecure Channels Based on Short Authenticated Strings* (SAS), CRYPTO 2005.
20. RFC 4251/4253 — *SSH Protocol Architecture / Transport Layer* (نموذج الثقة TOFU وبصمات المضيف).

## المكتبات والأدوات
21. Python `cryptography` — https://cryptography.io/en/latest/
    - X25519: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
    - Ed25519: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
    - AESGCM: https://cryptography.io/en/latest/hazmat/primitives/aead/
    - HKDF: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
22. Flask — https://flask.palletsprojects.com/
23. ifaddr — https://github.com/ifaddr/ifaddr
24. Python `socket`, `socketserver` — https://docs.python.org/3/library/socket.html
25. Windows `netsh advfirewall` — https://learn.microsoft.com/windows-server/networking/technologies/netsh/netsh-contexts
26. Mermaid (المخططات) — https://mermaid.js.org/
27. OWASP — *Cryptographic Storage Cheat Sheet* و *Cross-Site Request Forgery Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/

## كتب مقترحة
28. J.-P. Aumasson, *Serious Cryptography*, No Starch Press, 2017 (2nd ed. 2024).
29. N. Ferguson, B. Schneier, T. Kohno, *Cryptography Engineering*, Wiley, 2010.
30. W. Stallings, *Cryptography and Network Security: Principles and Practice*, Pearson.
