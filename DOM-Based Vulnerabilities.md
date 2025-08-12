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
