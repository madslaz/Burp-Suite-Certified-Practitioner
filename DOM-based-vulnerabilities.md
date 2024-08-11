## DOM XSS using web messages
- If a page handles web messages in an unsafe way, for example, by not verifying the origin of incoming messages correctly in the event listener, properties and functions that are called by the event listener can potentially become sinks. 
- For example, an attacker cost host a malicous `iframe` and user the `postMessage()` method to pass web message data to the vulnerable event listener, which then sends the payload to a sink on the parent page. 
- Impact of the vulnerability depends on the destination document's handling of the incoming message. If the destination document trusts the sender not to transmit malicious data in the message, and handles data in an unsafe way by passing it into a sink, then the joint behavior of the two documents may allow an attacker to compromise the user. 
- Consider the following code:
```
<script>
window.addEventListener('message', function(e) {
  eval(e.data);
});
</script>
```
- A JavaScript payload can be constructed with the following `iframe`: `<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">`
- As the event listener does not verify the origin of the message, and the `postMessage()` method specifies the `targetOrigin` `"*"`, the event listener accepts the payload and passes it into a sink, in this case, the `eval()` function. 
