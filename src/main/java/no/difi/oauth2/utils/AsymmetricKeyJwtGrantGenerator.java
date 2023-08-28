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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class AsymmetricKeyJwtGrantGenerator {


    public static void main(String[] args) throws Exception {

        // Variable som kommer fra integrasjonen
        String key_id = "__KID__"; // Key id (kid)
        String integrasjonsid = "__CLIENT_ID__";
        String scope = " __SCOPE__";

        // Variable som avhengiger av miljø
        String maskinportenAudience = "__MASKINPORTEN_URL__";
        String maskinportenTokenUrl = "__MASKINPORTEN_TOKEN_URL__";

        // Variable som avhenger av APIet du skal autentisere mot
        String targetApiAudience = "<your intended audience>"; // Sjekk API-tilbyder om de spesifiserer en verdi for denne

        // Variable som er tilpasset din keystore hvor du har lagt privatnøkkelen
        String keyStoreType = "PKCS12";
        String keystorepassword = "keystorepassword";
        String pathToKeystore = "pathToKeystore";
        String aliasToPrivatekey = "privatekey-alias";


        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(new FileInputStream(pathToKeystore), keystorepassword.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(aliasToPrivatekey);

        List<Base64> certChain = new ArrayList<>();
        certChain.add(Base64.encode(certificate.getEncoded()));

        JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(key_id)
                .build();


        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(maskinportenAudience)
                .claim("resource", targetApiAudience)
                .issuer(integrasjonsid)
                .claim("scope", scope)
                .jwtID(UUID.randomUUID().toString()) // Must be unique for each grant
                .issueTime(new Date(Clock.systemUTC().millis())) // Use UTC time
                .expirationTime(new Date(Clock.systemUTC().millis() + 120000)) // Expiration time is 120 sec
                .build();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(aliasToPrivatekey, keystorepassword.toCharArray());
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
