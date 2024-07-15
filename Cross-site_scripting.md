## Reflected XSS into HTML context with nothing encoded
- Simple payload required, such as `<script>alert(1)</script>`
- Can also play with payloads from this PortSwigger [cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#classic-vectors-xss-crypt)

## Stored XSS into HTML context with nothing encoded

![image](https://github.com/user-attachments/assets/bc19cd7d-f5f9-483c-82fd-65b85149f4d4)




 
## Miscellaneous Notes
- Chrome version 92 onward, cross-origin iframes are prevented from calling alert(). PoC payload needs to be altered, so using something like print() function. 
