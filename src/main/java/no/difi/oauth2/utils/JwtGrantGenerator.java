package no.difi.oauth2.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.hc.client5.http.fluent.Form;
import org.apache.hc.client5.http.fluent.Request;
import org.apache.hc.client5.http.fluent.Response;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;

import java.time.Clock;
import java.util.*;

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

        JWSHeader jwtHeader;
        if (config.hasKid()) {
            jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(config.getKid())
                    .build();
        } else {
            jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .x509CertChain(certChain)
                    .build();
        }

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
        try {
            Response response = Request.post(config.getTokenEndpoint())
                    .bodyForm(body)
                    .execute();

            HttpEntity e = ((BasicClassicHttpResponse) response.returnResponse()).getEntity();
            return EntityUtils.toString(e);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}