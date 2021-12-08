# Description
This is a spring-boot web MVC application implementing the OIDC authentication-code grant-type.  
This implementation uses the [nimbus-oauth-openid-connect-sdk](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)
to manage the interaction with the OP and the signature verification.  

This webapp provides some web pages in order to trigger the authentication process and call a resource (*user-info*) using
the access-token obtained from the grant flow.  

This application has been manually tested by connecting to a [Keycloak](https://www.keycloak.org/) instance.

## Disclaimer
I am not a security expert. Please do not take this implementation as a reference, as I may have missed some basics here.

# Setup and use
1. Configure the required properties in the *src/main/resources/application.properties* file. The required properties are 
documented in this file.
2. Build the maven project with ```mvn build```.
3. Launch the jar built in the *target folder*: ```java -jar <jar_filename>```
4. Once the webapp is ready, access is URL from a browser: ```http://localhost:<port>/```

# TODO
* Implement tests: for unit testing, this may be tricky as the [nimbus-oauth-openid-connect-sdk](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)
library does use the dependency injection pattern. HTTP calls are difficult to mock. Maybe using some integration tests 
where a 'fake' HTTP server with static response could be used...
* improve web pages CSS
* Encapsulate and abstract the OIDC client. The [nimbus-oauth-openid-connect-sdk](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk)
library's models are spread through the controller. Some intermediate POJO may be used to create a proper interface.