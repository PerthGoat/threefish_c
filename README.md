# Threefish C

---

This is a Threefish implementation for 256-bit key-size in a single .c file. I made this mainly because I wanted an easy reference to how exactly Threefish worked, because I liked the simplicity of the encryption algorithm and the fact that it supports key sizes greater than 256 bits (remember when 128-bit used to be enough?). This was made possible with the Threefish documentation found at:

https://en.wikipedia.org/wiki/Threefish

and

https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf

Threefish is part of the Skein hash function which isn't that great, but Threefish high key-size support is a very valuable thing and one of the great things to come out of the Skein hash project.

In addition, Threefish has not been broken, and as a result has extremely hard to break complexity. Where AES-256 I fear will be broken and all encrypted content rendered insecure, I feel secure in the knowledge that Threefish encrypted content may remain secure past the point where modern hardware is able to crack AES-256 as it did with AES-128.