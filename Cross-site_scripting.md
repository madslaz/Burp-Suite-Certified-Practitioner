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
- [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) - Burp browser tool that tests for DOM XSS vulnerabilities using a variety of sources and sinks, including both web message and prototype pollution vectors.

![image](https://github.com/user-attachments/assets/6d7f333a-09ce-4657-8656-a407ef72a251)

![image](https://github.com/user-attachments/assets/212351b1-da89-41ed-8e87-361162dfb08c)

- When we search something, such as `test`, we can see that it is inserted in the following script. Let's end the source tag and insert a payload, such as `"'><image+src+onerror%3dalert(1)>` (example given by Burp is `"><svg onload=alert(1)>`):
```
function trackSearch(query) {
 document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
  }
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
 trackSearch(query);
}
```

![image](https://github.com/user-attachments/assets/afd91667-b956-4e0d-9c79-45b715c4711a)


- When I really worked through the above, I constructed: `" <body onload=alert(1)>`.

## DOM XSS in `document.write` sink using source `location.search` inside a select element
- We are told there is a DOM XSS vulnerability in the stock checker functionality of this web application. It uses the JS function, `document.write` which writes data out to a page. The `document.write` function is called with data from `location.search` which you can control via the URL...
- When we examined the script, we can see that the storeId can be provided as a parameter in the URL. It is used within a <select element>:

![image](https://github.com/user-attachments/assets/4caf2da5-f1eb-479e-93e8-cb2ea52b0e5c)

![image](https://github.com/user-attachments/assets/7cd720e7-9daa-4c58-a50f-6d156b921331)

- `</select><svg onload=alert(1)>`, `storeId=Paris</select><body onload=alert(1)>`

## DOM XSS in jQuery anchor href attribute sink using location.search source

 
## Miscellaneous Notes
- Chrome version 92 onward, cross-origin iframes are prevented from calling alert(). PoC payload needs to be altered, so using something like print() function.
- A source is a JS property that accepts data that is potentially attacker-controlled. An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control.
  - Ultimately, any source controlled by the attacker is a potential source. Including the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by `document.cookie` string), and web messages.
- A sink is a potentially dangerous JS function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the `eval()` function is a sink because it processes the argument that is passed to it as JS. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JS. 
- Most common source is the URL, which is typically access with the `location` object. Consider the following code:
```
goto = location.hash.slice(1)
if (goto.startsWith('https:')) {
  location = goto;
}
```
 - If the URL contains a hash fragment that starts with https:, the code extracts the value of the `location.hash` property and sets it as the `location` property of the `window`. An attacker could exploit this with: `https://www.innocent-website.com/example#https://www.evil-user.net`

![image](https://github.com/user-attachments/assets/2f5beb64-03aa-4485-8ddd-bd1b7274b0ba)

![image](https://github.com/user-attachments/assets/3d5a123f-7d92-4ac6-ac13-4ece1dfc50ad)
