package no.difi.oauth2.utils;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import java.time.Clock;
import java.util.*;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.hc.client5.http.fluent.Content;
import org.apache.hc.client5.http.fluent.Form;
import org.apache.hc.client5.http.fluent.Request;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtGrantGenerator {

    public static void main(String[] args) throws Exception {

        Configuration config = Configuration.load(args);

        String jwt = makeJwt(config);
        if (config.getJsonOutput()) {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> output = new HashMap<>();
            output.put("grant", jwt);
            if (config.hasTokenEndpoint()) {
                output.put("token", mapper.readValue(makeTokenRequest(jwt, config), Object.class));
            }
            System.out.println(mapper.writeValueAsString(output));
        } else {
            System.out.println("Generated JWT-grant:");
            System.out.println(jwt);

            if (config.hasTokenEndpoint()) {
                System.out.println("\nRetrieved token-response:");
                System.out.println(makeTokenRequest(jwt, config));
            }
        }
    }

    private static String makeJwt(Configuration config) throws Exception {

        List<Base64> certChain = new ArrayList<>();
        certChain.add(Base64.encode(config.getCertificate().getEncoded()));

        JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .x509CertChain(certChain)
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(config.getAud())
                .claim("resource", config.getResource())
                .issuer(config.getIss())
                .claim("scope", config.getScope())
                .claim("consumer_org", config.getConsumerOrg())
                .jwtID(UUID.randomUUID().toString()) // Must be unique for each grant
                .issueTime(new Date(Clock.systemUTC().millis())) // Use UTC time!
                .expirationTime(new Date(Clock.systemUTC().millis() + 120000)) // Expiration time is 120 sec.
                .build();

        JWSSigner signer = new RSASSASigner(config.getPrivateKey());
        SignedJWT signedJWT = new SignedJWT(jwtHeader, claims);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private static String makeTokenRequest(String jwt, Configuration config) throws Exception {

        List body = Form.form()
                .add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .add("assertion", jwt)
                .build();

        Content response = Request.Post(config.getTokenEndpoint())
                .bodyForm(body)
                .execute()
                .returnContent();

        return response.asString();

    }

}
