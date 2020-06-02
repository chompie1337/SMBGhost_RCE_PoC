# SMBGhost_RCE_PoC

RCE PoC for CVE-2020-0796 "SMBGhost"

For demonstration purposes only! Seriously. This has not been tested outside of my lab environment.

Replace payload in USER_PAYLOAD in exploit.py

lznt1 code from [here](https://github.com/you0708/lznt1). Modified to add a "bad compression" option to corrupt SRVNET buffer
header without causing a crash.

See Ricera Security write up for more details on this interesing exploit method: 
https://ricercasecurity.blogspot.com/2020/04/ill-ask-your-body-smbghost-pre-auth-rce.html

