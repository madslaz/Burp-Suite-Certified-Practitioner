## HTTP Request Smuggling

### Overview
- Interfering with the way a site processes sequences of HTTP requests received from one or more users
- Usually allows bypassing security controls, gaining of unauthorized access, compromising other users 
- Primarily associated with HTTP/1 requests; however, some HTTP/2 vulnerable depending on backend architecture
- Today's web apps usually employ chains of HTTP servers between users and the ultimate logic: users send requests to the frontend server (sometimes called a load balancer or reverse proxy) and this server forwards the request(s) to one or more backend servers. 
- Typically, when the frontend server forwards HTTP requests to the backend server, it sends several requests over the same connection for efficiency and performance. HTTP requests are sent one after another, and the receiving server has to determine where one request ends and the next one begins: 

![User Requests from Frontend to Backend](Photos/forwarding-http-requests-to-back-end-server.svg)

- An attacker can try and trick the backend server. For example, an attacker might send an ambiguous request that gets interpreted differently by the frontend and the backend systems. In this example, the attacker causes part of their frontend request to be interpreted by the backend server as the start of the next request. It is effectively prepended to the next request and can interfere with the way the application processes that request:

![alt text](Photos/smuggling-http-request-to-back-end-server.svg)

### How Does This Happen?

- HTTP/1 specification provides two different ways to specify where a request ends:
    1. `Content-Length` header: Pretty straightforward. Specifies the length of the message body in bytes. 
    2. `Transfer-Encoding` header: Specify that the message body uses chunked encoding. Means that the message body contains one or more chunks of data. Each chunk consists of the chunk size in bytes (expressed in a hexadecimal), followed by a newline, followed by the chunk contents. Terminated with a chunk of size zero. For example, hexadecimal of B is 11 (binary: 1011), so b for q=smuggling.

```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```
- Burp Suite auto unpacks chunked encoding to make messages easier to view and edit. Browsers do not normally use chunked encoding in requests, and it is normally seen only in server responses. 
- Since the HTTP/1 specification provides two different methods for specifying the length of HTTP messages, it is possible for a single message to use both methods at once, such that they conflict with each other. The specification attempts to prevent this problem by stating if both the `Content-Length` and `Tranfer-Encoding` headers are present, then the `Content-Length` header should be ignored. This may be sufficient to avoid ambiguity when only a single server is in play, but not when two or more servers are chained together. In this situation, problems can arise for two reasons:
    1. Some servers do not support the `Transfer-Encoding` header in requests
    2. Some servers that do support the `Transfer-Encoding` header can be induced not to process it if the header is obfuscated in some way
- If the frontend and backend servers behave differently in relation to the (possibly obfuscated) `Transfer-Encoding` header, then they might disagree about the boundaries betwen successive requests, leading to request smuggling vulnerabilities. 
- HTTP/2 end-to-end is inherently immune to request smuggling as it introduces a single, robust mechanism for specifying the length of a request. There is no way for an attacker to introduce the required ambiguity. HOWEVER, many websites have HTTP/2 frontend, but deploy backend infrastructure that only supports HTTP/1. This means frontend has to translate the requests it receives to HTTP/1. Known as HTTP downgrading - more on this in more advanced request smuggling. 

### How to Perform Request Smuggling