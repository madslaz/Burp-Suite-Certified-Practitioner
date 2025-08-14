## DOM-Based Vulnerabilities 

### DOM XSS Using Web Messages
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

### DOM XSS Using Web Messages and JavaScript URL
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
- I struggled with constructing the payload here. I knew it needed to have `https:` or `http:`, and I knew it was a JavaScript URL. I attempted `<iframe src="https://0aad00b0039dc1f980ba1c2e003f00ae.web-security-academy.net/" width="2000" height="2000" onload="this.contentWindow.postMessage('javascript:print(); http:','*')">` thinking the semicolon would terminate it, but I wasn't really considering the rest of the message - the http:. What I needed to do instead was comment out the rest with JavaScript comment, `//`. 
