## Basic SSRF against the local server
- We know the lab has an SSRF vulnerability related to the stock check feature, which uses the following paramter `stockApi` to call http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1. We can replace this URL with http://127.0.0.1/admin. URL-encoding was not necessary here.
- We can utilize the returned result to generate the proper URL to delete carlos: `/admin/delete?username=carlos`

![image](https://github.com/madslaz/Burp-Suite-Certified-Practitioner/assets/52518274/584304c6-15f4-4bc4-bdc6-e7210f4f7838)
