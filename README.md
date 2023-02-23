# jwt-grant-generator

This project demonstrates how clients of Maskinporten can make a jwt grant used to retrieve tokens for accessing services like Kontakt- og reservasjonsregisteret REST-API or ID-porten self-service APIs.

Before you can retrieve any tokens you need to be a customer of Digdir and have a client registration, see https://samarbeid.digdir.no

It is important to understand the authorization flow used for these apis, see https://docs.digdir.no/docs/Maskinporten/maskinporten_guide_apikonsument 

Note: The access token is only retrieved if an token.endpoint property is given. Without this a jwt bearer grant will only be printed.

For questions, please contact servicedesk@digdir.no

### Client configuration
To generate a jwt-grant you need a property file holding your client configuration:

```
issuer=<Your client_id>
audience=<Identifier of the Maskinporten instance you want to use, i.e. for ver2 env:  https://ver2.maskinporten.no/>
resource=<The intended audience for token. If included, the value will be transparantly set as the aud-claim in the access token>
scope=<scopes to request access for (space delimited list), i.e. for id-porten self service api use: idporten:dcr.read idporten:dcr.write>

keystore.type=<keystore type, default is JKS>
keystore.file=<path to your keystore file holding your virksomhetssertifikat / keypair, or base64-encoded keystore>
keystore.password=<keystore password>
keystore.alias=<alias for your virksomhetssertifikat's key>
keystore.alias.password=<alias password>

```

To use base64-encoded keystore, use:

```
keystore.file=base64:/u3+7QAAAAIAAAADAAAAAQAPY29tbWZp...
```

To also retrieve an access-token from an authorization server, add this property to the properties file:

```
token.endpoint=<Token endpoint to use, i.e. in ver2 env: https://ver2.maskinporten.no/token>
```

If you want to generate a token utilising the delegation capabilities in Maskinporten, add this property to the properties file:
```
consumer_org=<the orgnumber of the consumer that has delegated the access>
```

You may authenticate with a self-signed certificate if your client in Maskinporten holds a JSON Web Key Set with your public key, simply add your key ID to the properties file:
```
keystore.kid=<guid to key id used in Maskinporten client jwks>
```

## Usage

To build and run use:

```
mvn package

java -jar target\jwt-grant-generator-1.0-SNAPSHOT-jar-with-dependencies.jar myclient.properties

```

### Output as JSON
If you want the response as json, you can add an additional parameter so the command to build and run is
```
mvn package

java -jar target\jwt-grant-generator-1.0-SNAPSHOT-jar-with-dependencies.jar myclient.properties json

```

The JSON will be a single line so it is easy to capture in a script and can then be parsed with tools like jq.
A pretty representation of the JSON schema is
```
{
    "grant": "...",
    "token": {
        "access_token": "...",
        "token_type": "Bearer",
        "expires_in": 7199,
        "scope": "..."
    }
}

```
