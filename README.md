# BurpSuite-API-sign-plugins

Two example of HMAC signing for API.

First you need input creds you have, including domain of request and your secret key.

Second, you need jython-standalone-2.5.4-rc1.jar connected to your BurpSuite (Extender -> Options -> Python Environment)

Then, you need to enable extension. Add it to your extender, then click to Project Options -> Sessions -> Session Handling Rules -> Add.
Add Rule Action - Invoke a Burp Extension, then choose extension. Then click on "Scope" and choose where you need to invoke it. Press "Ok"
