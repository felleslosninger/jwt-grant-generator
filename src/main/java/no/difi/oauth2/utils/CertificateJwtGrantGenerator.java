package no.difi.oauth2.utils;

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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.*;

public class CertificateJwtGrantGenerator {

    public static void main(String[] args) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        String keystorepassword = "keystorepassword";
        String alias = "keystore cert alias";

        keyStore.load(new FileInputStream("pathToKeystore"), keystorepassword.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

        List<Base64> certChain = new ArrayList<>();
        certChain.add(Base64.encode(certificate.getEncoded()));

        JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .x509CertChain(certChain)
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("TODO maskinporten-miljø")
                .claim("resource", "<your intended audience>")
                .issuer("__CLIENT_ID__")
                .claim("scope", "__SCOPE__")
                .jwtID(UUID.randomUUID().toString()) // Must be unique for each grant
                .issueTime(new Date(Clock.systemUTC().millis())) // Use UTC time!
                .expirationTime(new Date(Clock.systemUTC().millis() + 120000)) // Expiration time is 120 sec.
                .build();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keystorepassword.toCharArray()); // Read from KeyStore
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJWT = new SignedJWT(jwtHeader, claims);
        signedJWT.sign(signer);

        String jwt = signedJWT.serialize();

        List body = Form.form()
                .add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .add("assertion", jwt)
                .build();
        try {
            Response response = Request.post("TODO tokenendpoint")
                    .bodyForm(body)
                    .execute();

            HttpEntity e = ((BasicClassicHttpResponse) response.returnResponse()).getEntity();
            String result = EntityUtils.toString(e);

            // Use access_token in result as authentication header to the service you wish to connect to

        } catch (Exception e) {
            e.printStackTrace();
        }


    }

}
