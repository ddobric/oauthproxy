# What is OAuthProxy

The OAuthProxy is a very simple web application build on top of ASP.NET Core that authenticate the user aganist one of selected social or business provider.
After the user is authenticated the obrained  *id-token* issued by the provider is used to create the new JWT id-token, that is passed bac the the application.

<img src="assets/OAuthProxy Architecture.png"></img>

When the SPA application like Blazor WASM standalone starts (1) at some moment the user might be required to logon. The BlazorApp reads the appSettings section
that contains the *Authority*, which specifies the OAuthProxy. On long the app will simply redirect to the OAuthProxy (authority) and provides its
base URL as a callback. The app will genarate following request (2):

~~~
https://oauthproxy.com/?callback=https://blazorapp.com  
~~~

The OAuthProxy is a very simple webapplication that authenticates user, by chosen provider. Once the user is authenticated the webapplication will receive the JWT *id-token*.
The trusted information is used to create the new JWT token issued by OAuthProxy. This is the oportunity for developers to
create the token with any kind of claims similarly as idenetity server does it.

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

