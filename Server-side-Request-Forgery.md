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
