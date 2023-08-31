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
import org.apache.hc.core5.http.ContentType;
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

        // Variable som kommer fra integrasjonen
        String integrasjonsid = "__CLIENT_ID__";
        String scope = "__SCOPE__";

        // Variable som avhengiger av miljø
        String maskinportenAudience = "__MASKINPORTEN_URL__";
        String maskinportenTokenUrl = "__MASKINPORTEN_TOKEN_URL__";

        // Variable som avhenger av APIet du skal autentisere mot
        String targetApiAudience = null; // Optional: Sjekk API-tilbyder om de spesifiserer en verdi for denne

        // Variable som er tilpasset din keystore hvor du har lagret virksomhetssertifikatet ditt
        String keystoreType = "PKCS12";
        String pathToKeystore = "pathToKeystore";
        String keystorepassword = "keystorepassword";
        String aliasToVirksomhetssertifikat = "virksomhetsserifikat-alias";
        String aliasPassword = "myaliaspassword";

        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        keyStore.load(new FileInputStream(pathToKeystore), keystorepassword.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(aliasToVirksomhetssertifikat);

        List<Base64> certChain = new ArrayList<>();
        certChain.add(Base64.encode(certificate.getEncoded()));

        JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .x509CertChain(certChain)
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(maskinportenAudience)
                .issuer(integrasjonsid)
                .claim("scope", scope)
                .claim("resource", targetApiAudience)
                .jwtID(UUID.randomUUID().toString()) // Must be unique for each grant
                .issueTime(new Date(Clock.systemUTC().millis())) // Use UTC time
                .expirationTime(new Date(Clock.systemUTC().millis() + 120000)) // Expiration time is 120 sec
                .build();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(aliasToVirksomhetssertifikat, aliasPassword.toCharArray());
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJWT = new SignedJWT(jwtHeader, claims);
        signedJWT.sign(signer);

        String jwt = signedJWT.serialize();

        List body = Form.form()
                .add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .add("assertion", jwt)
                .build();
        try {
            Response response = Request.post(maskinportenTokenUrl)
                    .addHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.toString())
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
