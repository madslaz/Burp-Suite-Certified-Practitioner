## Basic SSRF against the local server
- We know the lab has an SSRF vulnerability related to the stock check feature, which uses the following paramter `stockApi` to call http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1. We can replace this URL with http://127.0.0.1/admin. URL-encoding was not necessary here.
- We can utilize the returned result to generate the proper URL to delete carlos: `/admin/delete?username=carlos`

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/584304c6-15f4-4bc4-bdc6-e7210f4f7838)

## Basic SSRF against another back-end system
- Lab has stock check feature that fetches data from internal system with SSRF vulnerability. We need to scan 192.168.0.x for an admin interface on port 8080.

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/cd4789a7-6061-4278-a828-1bfaa94d5a7e)

- Noted 200 OK response to .235. Utilized payload similar to previous lab to delete `carlos`. `stockApi=http%3A%2F%2F192.168.0.235%3A8080%2Fadmin/delete%3fusername%carlos`


