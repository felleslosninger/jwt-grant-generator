package no.difi.oauth2.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class Configuration {

    private String iss;
    private String aud;
    private String resource;
    private String scope;
    private String tokenEndpoint;
    private X509Certificate certificate;
    private PrivateKey privateKey;
    private String consumerOrg;
    private Boolean jsonOutput = false;
    private String kid;

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getResource() {
	return resource;
    }

    public void setResource(String resource) { this.resource = resource; }

    public String getConsumerOrg() {
        return consumerOrg;
    }

    public void setConsumerOrg(String consumerOrg) {
	this.consumerOrg = consumerOrg;
    }

    public Boolean getJsonOutput() {
        return jsonOutput;
    }

    public void setJsonOutput(Boolean jsonOutput) {
        this.jsonOutput = jsonOutput;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public boolean hasTokenEndpoint() {
        return tokenEndpoint != null;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public boolean hasKid() {
        return kid != null;
    }

    public static Configuration load(String[] args) throws Exception {
        Configuration config = new Configuration();

        if (args != null && args.length >= 1 && args[0] != null) {

            Properties props = readPropertyFile(args[0]);

            config.setIss(props.getProperty("issuer"));
            config.setAud(props.getProperty("audience"));
            config.setResource(props.getProperty("resource"));
            config.setConsumerOrg(props.getProperty("consumer_org"));
            config.setScope(props.getProperty("scope"));
            config.setTokenEndpoint(props.getProperty("token.endpoint"));

            String keystoreFile = props.getProperty("keystore.file");
            String keystorePassword = props.getProperty("keystore.password");
            String keystoreAlias = props.getProperty("keystore.alias");
            String keystoreAliasPassword = props.getProperty("keystore.alias.password");

            config.setKid(props.getProperty("keystore.kid"));

            loadCertificateAndKeyFromFile(config, keystoreFile, keystorePassword, keystoreAlias, keystoreAliasPassword);
            if (args.length == 2 && args[1].equals("json")) {
                config.setJsonOutput(true);
            }

        } else {
            System.out.println("Usaga: java -jar jwtgrant.jar <property file name>");
            System.exit(0);
        }

        return config;
    }

    private static void loadCertificateAndKeyFromFile(Configuration config, String keyStoreFile, String keyStorePassword, String alias, String keyPassword) throws Exception {
       InputStream is = new FileInputStream(keyStoreFile);
       loadCertificate(config, is, keyStorePassword, alias, keyPassword);

    }

    private static void loadCertificate(Configuration config, InputStream is, String keystorePassword, String alias, String keyPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(is, keystorePassword.toCharArray());

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray()); // Read from KeyStore
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

        config.setCertificate(certificate);
        config.setPrivateKey(privateKey);
    }

    private static Properties readPropertyFile(String filename) throws Exception {
        Properties props = new Properties();

        InputStream inputStream = new FileInputStream(filename);
        if (inputStream != null) {
            props.load(inputStream);
        } else {
            throw new FileNotFoundException("property file '" + filename + "' not found in the classpath");
        }

        return props;
    }

}

