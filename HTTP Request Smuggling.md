## HTTP Request Smuggling
- Interfering with the way a site processes sequences of HTTP requests received from one or more users
- Usually allows bypassing security controls, gaining of unauthorized access, compromising other users 
- Primarily associated with HTTP/1 requests; however, some HTTP/2 vulnerable depending on backend architecture
- Today's web apps usually employ chains of HTTP servers between users and the ultimate logic: users send requests to the frontend server (sometimes called a load balancer or reverse proxy) and this server forwards the request(s) to one or more backend servers. 
- Typically, when the frontend server forwards HTTP requests to the backend server, it sends several requests over the same connection for efficiency and performance. HTTP requests are sent one after another, and the receiving server has to determine where one request ends and the next one begins: 


![alt text](Photos/forwarding-http-requests-to-back-end-server.svg)