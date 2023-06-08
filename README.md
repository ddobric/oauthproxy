# What is OAuthProxy

The OAuthProxy is a straightforward web application developed using ASP.NET Core. It serves the purpose of authenticating users against various social or business providers. Once the user is authenticated, the received id-token from the provider is utilized to generate a new JWT id-token, which is then returned to the application. The OAuthProxy is designed to assist developers in implementing their own identity provider solutions.

<img src="assets/OAuthProxy Architecture.png"></img>

When the application, like Blazor WASM standalone (just an example), starts (1), at some point the user might be required to log on. The BlazorApp reads the appSettings section that contains the Authority, which specifies the OAuthProxy. Along the way, the app will simply redirect to the OAuthProxy (authority) and provide its base URL as a callback. The app will generate the following request (2):

~~~
https://oauthproxy.com/?callback=https://blazorapp.com  
~~~

Once the user is authenticated, the web application receives the JWT id-token. This trusted information is used to create a new JWT token issued by the OAuthProxy. This provides developers with the opportunity to create tokens with any kind of claims, similar to how an identity server does it.

To create the token following configuration is used.

~~~
  "JwtTokenCreatorConfig": {

    "Issuer": https://oauthproxy.com/identityserver,
    "Audience": https://oauthproxy.com/api,
    "Secret": "STRONGKEY",
    "Kid":  "ANYSTRING"
  }
~~~

**Issuer**
The *issuer* is the defines your own issuer as the authority that creates the token. Use any valid URL as a value.

**Audience**
The *audience* is any valid audience that specifies the purpose of the token. This audience will be later validated by some REST API.

**Secret**
The *secret* is any string (Sypher) that will be used to sign the token. The same secret must be configured by the REST API that will possibly deal with this token.

**Kid**
The *kid* is the key identifier. When the token is signed with the key, the token will hold in the header the key identifier. The token validating application
like some REST Api will typically be used the *kid* to look up the key and validate the signature of the token.
By using the *kid* and *secret* the trust between the RESP Api and OAuthProxy is established.

Following snippet shows the JWT token created by the OAuthProxy:
 
~~~
{
  "alg": "HS256",
  "kid": http://daenet.com/oauthproxy/instance-zero,
  "typ": "JWT"
}
{
  "provider": "Google/Microsoft/..",
  "nameid": "106***496",
  "email": useralias@domain.com,
  "given_name": “FirstName",
  "unique_name": “Firstname LastName",
  "nbf": 1617031439,
  "exp": 1617636239,
  "iat": 1617031439,
  "iss": https://oauthproxy.com/identityserver,
  "aud": https://oauthproxy.com/api
}
~~~

### Creating custom tokens
If you want to customize the token please overwrite the method *GenerateToken*. In this method you can implement any code that looks up your own database 
and create set of required claims. it is extrimely simple way to create JWT tokens without of need too hook into ASP.NET extensibility system.

