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

public class JwtGrantGenerator {


    public static void main(String[] args) throws Exception {

        Configuration config = Configuration.load(args);

        String jwt = makeJwt(config);
        System.out.println(jwt);
    }

    private static String makeJwt(Configuration config) throws Exception {

        List<Base64> certChain = new ArrayList<>();
        certChain.add(Base64.encode(config.getCertificate().getEncoded()));

        JWSHeader jwtHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.x509CertChain(certChain)
				.build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(config.getAud())
                .issuer(config.getIss())
                .claim("scope", config.getScope())
                .jwtID(UUID.randomUUID().toString()) // Must be unique for each grant
                .issueTime(new Date(Clock.systemUTC().millis())) // Use UTC time!
                .expirationTime(new Date(Clock.systemUTC().millis() + 120000)) // Expiration time is 120 sec.
                .build();

        JWSSigner signer = new RSASSASigner(config.getPrivateKey());
        SignedJWT signedJWT = new SignedJWT(jwtHeader, claims);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

}