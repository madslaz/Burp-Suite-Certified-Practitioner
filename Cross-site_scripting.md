## Reflected XSS into HTML context with nothing encoded
- Simple payload required, such as `<script>alert(1)</script>`
- Can also play with payloads from this PortSwigger [cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#classic-vectors-xss-crypt)

## Stored XSS into HTML context with nothing encoded
- Tested all sections required for a comment. Email and website required strict formats. Inserted payload `<body onpageshow=alert(1)>` in both name field and comment field. Confirmed later execution only triggered by comment field. 
![image](https://github.com/user-attachments/assets/bc19cd7d-f5f9-483c-82fd-65b85149f4d4)

## DOM XSS in `document.write` sink using source `location.search`
- DOM-based XSS may arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as `eval()` or `innerHTML`. To exexcute DOM-based XSS, you need to place the data into a source so that it is propagated to a sink and cases execustion of arbitrary JavaScript.
- Most common source of DOM-based XSS is the URL, which is typically accessed with `window.location` object. The payload is often put in the query string; however, when targeting a 404 page or website running PHP, the payload can also be placed in the path.
- See more at [DOM-based vulnerabilities page](https://portswigger.net/web-security/dom-based)
- 


 
## Miscellaneous Notes
- Chrome version 92 onward, cross-origin iframes are prevented from calling alert(). PoC payload needs to be altered, so using something like print() function.
- A source is a JS property that accepts data that is potentially attacker-controlled. An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control.
  - Ultimately, any source controlled by the attacker is a potential source. Including the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by `document.cookie` string), and web messages.
- A sink is a potentially dangerous JS function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the `eval()` function is a sink because it processes the argument that is passed to it as JS. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JS. 
