## Basic SSRF against the local server
- We know the lab has an SSRF vulnerability related to the stock check feature, which uses the following paramter `stockApi` to call http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1. We can replace this URL with http://127.0.0.1/admin. URL-encoding was not necessary here.
- We can utilize the returned result to generate the proper URL to delete carlos: `/admin/delete?username=carlos`

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/584304c6-15f4-4bc4-bdc6-e7210f4f7838)

## Basic SSRF against another back-end system
- Lab has stock check feature that fetches data from internal system with SSRF vulnerability. We need to scan 192.168.0.x for an admin interface on port 8080.

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/cd4789a7-6061-4278-a828-1bfaa94d5a7e)

- Noted 200 OK response to .235. Utilized payload similar to previous lab to delete `carlos`. `stockApi=http%3A%2F%2F192.168.0.235%3A8080%2Fadmin/delete%3fusername%carlos`

## Blind SSRF with out-of-band detection
- Replacing the URL within the Referer header with the collaborator server led to DNS/HTTP requests to the collaborator server.
` Referer: https://0a5600db0444816582834cdb005f007c.web-security-academy.net/` --> `https://e7mjolx5b88gflhno0j8lpvqbhh950tp.rsmcollaborator.com/`

## SSRF with blacklist-based input filter
- Attempt to circumvent weak blacklisting through a few different methods:
  - Use an alternative IP representation of 127.0.0.1, such as `2130706433` (dotted decimal format), `017700000001`, (octal) or `127.1.`
    - [Article on IP Variations](https://ma.ttias.be/theres-more-than-one-way-to-write-an-ip-address/)
    - [GitHub for IP Obfuscater Tool](https://github.com/vysecurity/IPFuscator)
  - Register a domain that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net`
  - Obfuscate using URL encoding or case variation
  - Provide  URL that you can control which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, swithing http: to https:. URL during the redirect has been shown to bypass some anti-SSRF filters.
  - For this lab, we altered the IP address from 127.0.0.1 to 127.1 and then DOUBLE encoded the 'admin' payload: `http%3a//127.1/%25%36%31%64%25%36%64%25%36%39%25%36%65`

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/af3ffe4a-4a99-4dd4-a3ff-6e9a919745d7)

## SSRF with filter bypass via open redirection vulnerability
- Look for various URL paramters which could indicate redirection such as `url` and `path`. See more [here](https://github.com/lutfumertceylan/top25-parameter/blob/master/ssrf-parameters.txt)
- In this lab, we noted that the stock checker fetches data from an internal system, but it has been restricted to only access the local application. We, unfortunately, need to access `http://192.168.0.12:8080/admin` to delete the user `carlos`.
- We discovered that one of the features, 'Next Product' allows for an open redirection, as the `path` variable is inserted ... maybe we should take this URL and throw it in the stock checker - the stock checker can only access local apps, but with the open redirection, we are able to access the admin interface and delete `carlos` :)

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/74c66819-f88e-4591-a580-611f0665eea4)

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/3128bf9c-4feb-4102-9da5-3f62a670fff3)

## SSRF with whitelist-based input filter
- It is possible that web applications employ an allowlist that matches the input against a list of permitted values. It may look for a match at the beginning of the input or contained within it. You could bypass this filter by exploiting URL parsing inconsistencies. Some strategies include:
- Embedding credentials in a URL before the hostname: `https://expected-host:fakepassword@evil-host`
- Indicating a URL fragment with `#`, `https://evil-host#expected-host`
- Leveraging DNS naming hierarchy `https://expected-host.evil-host`
- Url-encoding (or double encoding)
- During this lab, we attempted various strategies; however, we noted the web application looked for an exact match of stock.weliketoshop.net. We did note you could embed credentials before, such as `http://user@stock.weliketoshop.net` without error. 
