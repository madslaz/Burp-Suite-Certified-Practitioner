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
  - 

#### OpenID Connect
- OpenID Connect extends the OAuth protocol to provide a dedicated identity and authentication layer that sits on top of the basic OAuth implementation. 
