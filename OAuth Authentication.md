#### OAuth 2.0 Authentication Vulnerabilities 
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

## Authorization code grant type
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



#### OpenID Connect
- OpenID Connect extends the OAuth protocol to provide a dedicated identity and authentication layer that sits on top of the basic OAuth implementation. 
