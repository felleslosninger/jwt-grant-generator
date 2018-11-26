# jwt-grant-generator

This project demonstrates how to make a jwt grant used to retrieve tokens for accessing Difi services like Kontakt- og reservasjonsregisteret REST-API or ID-porten self-service APIs.

Before you can retrieve any tokens you need to be a customer of DIFI and have a client registration, see https://samarbeid.difi.no

It is important to understand the authorization flow used for these apis, see https://difi.github.io/idporten-oidc-dokumentasjon/oidc_auth_server-to-server-oauth2.html

### Client configuration
To generate a jwt-grant you need a propery file holding your client configuration:

```
issuer=<Your client_id>
audience=<Identifier of the idporten-oidc-provider instance you want to use, i.e. for ver2 env:  https://oidc-ver2.difi.no/idporten-oidc-provider/>
token.endpoint=<Token endpoint to use, i.e. in ver2 env: https://oidc-ver2.difi.no/idporten-oidc-provider/token>
scope=<scopes to request access for (space delimited list), i.e. for id-porten self service api use: idporten:dcr.read idporten:dcr.write>

keystore.file=<path to your keystore file holding your virksomhetssertifikat / keypair>
keystore.password=<keystore password>
keystore.alias=<alias for your virksomhetssertifikat's key>
keystore.alias.password=<alias password>

```

## Usage

To build and run use:

```
mvn package

java -jar target\jwt-grant-generator-1.0-SNAPSHOT-jar-with-dependencies.jar myclient.properties

```