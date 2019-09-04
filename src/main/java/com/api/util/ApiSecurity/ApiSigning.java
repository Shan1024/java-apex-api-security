package com.api.util.ApiSecurity;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * @author GDS-PDD
 */
public class ApiSigning {

    private static final Logger log = LoggerFactory.getLogger(ApiSigning.class);

    /**
     * Create HMACRSA256 Signature (L1) with a given basestring
     *
     * @param baseString Signature Basestring to be Signed
     * @param secret     App Secret
     * @return HMACSHA256 Signature
     * @throws ApiUtilException
     */
    public static String getHMACSignature(String baseString, String secret) throws ApiUtilException {
        log.debug("Enter :: getHMACSignature :: baseString : {} , secret: {} ", baseString, secret);

        try {
            if (baseString == null || baseString.isEmpty()) {
                throw new ApiUtilException("baseString must not be null or empty.");
            }

            if (secret == null || secret.isEmpty()) {
                throw new ApiUtilException("secret must not be null or empty.");
            }

            // get an hmac_sha256 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HMACSHA256");

            // get an hmac_sha256 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance("HMACSHA256");
            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(baseString.getBytes(StandardCharsets.UTF_8));

            // base64-encode the hmac
            String base64Token = Base64.getEncoder().encodeToString(rawHmac);
            log.debug("Exit :: getHMACSignature :: base64Token : {} ", base64Token);

            return base64Token;
        } catch (ApiUtilException ae) {
            log.error("Error :: getHMACSignature :: " + ae.getMessage());
            throw ae;
        } catch (Exception e) {
            log.error("Error :: getHMACSignature :: " + e.getMessage());
            throw new ApiUtilException("Error during L1 Signature value generation", e);
        }
    }

    /**
     * Verify HMACSHA256 Signature (L1)
     *
     * @param signature  Signature to be verified
     * @param secret     App's Secret
     * @param baseString Basestring to be signed and compare
     * @return
     * @throws ApiUtilException
     */
    public static boolean verifyHMACSignature(String signature, String secret, String baseString) throws ApiUtilException {
        log.debug("Enter :: verifyHMACSignature :: signature : {} , baseString : {} , secret: {} ", signature,
                baseString, secret);

        String expectedSignature = getHMACSignature(baseString, secret);
        boolean verified = expectedSignature.equals(signature);

        log.debug("Exit :: verifyHMACSignature :: boolean : {}", verified);

        return verified;
    }

    /**
     * Get RSA256 Signature (L2)
     *
     * @param baseString Basestring to be signed and compare
     * @param privateKey Private Key
     * @return
     * @throws ApiUtilException
     */
    public static String getRSASignature(String baseString, PrivateKey privateKey) throws ApiUtilException {
        log.debug("Enter :: getRSASignature :: baseString : {} ", baseString);

        try {
            if (baseString == null || baseString.isEmpty()) {
                throw new ApiUtilException("baseString must not be null or empty.");
            }

            if (privateKey == null) {
                throw new ApiUtilException("privateKey must not be null.");
            }

            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(baseString.getBytes());

            byte[] encryptedData = rsa.sign();
            log.debug("encryptedData length:" + encryptedData.length);

            String base64Token = new String(Base64.getEncoder().encode(encryptedData));
            log.debug("Exit :: getRSASignature :: base64Token : {} ", base64Token);

            return base64Token;
        } catch (ApiUtilException ae) {
            log.error("Error :: getRSASignature :: " + ae.getMessage());
            throw ae;
        } catch (Exception e) {
            log.error("Error :: getRSASignature :: " + e.getMessage());
            throw new ApiUtilException("Error during L2 Signature value generation", e);
        }
    }

    /**
     * Verify RSA256 Signature (L2)
     *
     * @param baseString Basestring to be signed and compare
     * @param signature  Signature to be verified
     * @param publicKey  Corresponding Public Key to verify the signature
     * @return
     * @throws ApiUtilException
     */
    public static boolean verifyRSASignature(String baseString, String signature, PublicKey publicKey) throws ApiUtilException {
        log.debug("Enter :: verifyRSASignature :: baseString  : {} , signature : {} ", baseString, signature);

        try {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
            publicSignature.update(baseString.getBytes(StandardCharsets.UTF_8));

            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            boolean verified = publicSignature.verify(signatureBytes);

            log.debug("Exit :: verifyRSASignature");

            return verified;
        } catch (Exception e) {
            log.error("Error :: verifyRSASignature :: " + e.getMessage());
            throw new ApiUtilException("Error during L2 Signature verification", e);
        }
    }

    /**
     * Get Private key from Keystore
     *
     * @param keystoreFileName Keystore file Path
     * @param password         Keystore passsword
     * @param alias            Keystore's alias
     * @return private key
     * @throws ApiUtilException
     */
    public static PrivateKey getPrivateKeyFromKeyStore(String keystoreFileName, String password, String alias) throws ApiUtilException {
        log.debug("Enter :: getPrivateKeyFromKeyStore :: keystoreFileName : {} , password: {} , alias: {} ",
                keystoreFileName, password, alias);

        try {
            KeyStore ks = KeyStore.getInstance("JKS");

            // keystore and key password
            char[] passwordChar = password.toCharArray();

            // Try with resources which will auto close the stream.
            try (FileInputStream fis = new FileInputStream(keystoreFileName)) {
                ks.load(fis, passwordChar);
            }

            KeyStore.PrivateKeyEntry keyEnt = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
                    new KeyStore.PasswordProtection(passwordChar));
            PrivateKey privateKey = keyEnt.getPrivateKey();
            log.debug("Exit :: getPrivateKeyFromKeyStore");

            return privateKey;
        } catch (Exception e) {
            log.error("Error :: getPrivateKeyFromKeyStore :: " + e.getMessage());
            throw new ApiUtilException("Error while getting Private Key from KeyStore", e);
        }
    }

    /**
     * Get Public Key from Certificate
     *
     * @param publicCertificateFileName Certificate file path
     * @return Public Key
     * @throws ApiUtilException
     */
    public static PublicKey getPublicKeyFromX509Certificate(String publicCertificateFileName) throws ApiUtilException {
        log.debug("Enter :: getPublicKeyFromX509Certificate :: publicCertificateFileName : {} ",
                publicCertificateFileName);

        // Try with resources which will auto close the stream.
        try (FileInputStream fin = new FileInputStream(publicCertificateFileName)) {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
            PublicKey pk = certificate.getPublicKey();
            log.debug("Exit :: getPublicKeyFromX509Certificate");
            return pk;
        } catch (Exception e) {
            log.error("Error :: getPublicKeyFromX509Certificate :: " + e.getMessage());
            throw new ApiUtilException("Error while getting Public Key from X509 Certificate", e);
        }
    }

    /**
     * Get Public Key from PEM format file
     *
     * @param publicCertificateFileName PEM file path
     * @return Public Key
     * @throws IOException
     */
    public static PublicKey getPublicKeyPEM(String publicCertificateFileName) throws IOException {
        log.debug("Enter :: getPublicKeyPEM :: publicCertificateFileName : {} ", publicCertificateFileName);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Private key file in PEM format.
        File publicCertificateFile = new File(publicCertificateFileName);

        // Try with resources which will auto close the parser.
        try (PEMParser pemParser = new PEMParser(new FileReader(publicCertificateFile))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            SubjectPublicKeyInfo keyInfo;
            PublicKey key;
            KeyPair kp;
            if (object instanceof SubjectPublicKeyInfo) {
                keyInfo = (SubjectPublicKeyInfo) object;
                key = converter.getPublicKey(keyInfo);
            } else {
                kp = converter.getKeyPair(((PEMKeyPair) object));
                key = kp.getPublic();
            }
            log.debug("Exit :: getPublicKeyPEM");

            return key;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Formulate Signature BaseString
     *
     * @param authPrefix      Authorization Header scheme prefix , i.e 'prefix_appId'
     * @param signatureMethod Signature signing method
     * @param appId           App ID
     * @param urlPath         API Service URL
     * @param httpMethod      HTTP Operation
     * @param formList        form data
     * @param nonce           Random Nonce
     * @param timestamp       Timestamp
     * @return Base String for signing
     * @throws ApiUtilException
     */
    public static String getBaseString(String authPrefix, String signatureMethod, String appId, String urlPath,
                                       String httpMethod, ApiList formList, String nonce, String timestamp)
            throws ApiUtilException {
        log.debug("Enter :: getBaseString :: authPrefix  : {} , signatureMethod : {} , appId : {} , "
                        + "urlPath : {} , httpMethod : {} , nonce : {} , timestamp : {}", authPrefix, signatureMethod,
                appId, urlPath, httpMethod, nonce, timestamp);

        try {
            authPrefix = authPrefix.toLowerCase();

            // make sure that the url are valid
            URI siteUri;
            siteUri = new URI(urlPath);
            log.debug("raw url:: {}", urlPath);
            log.debug("siteUri.getScheme():: {}", siteUri.getScheme());

            if (!siteUri.getScheme().equals("http") && !siteUri.getScheme().equals("https")) {
                throw new ApiUtilException("Support http and https protocol only.");
            }

            String url;
            // make sure that the port no and querystring are remove from url
            if (siteUri.getPort() == -1 || siteUri.getPort() == 80 || siteUri.getPort() == 443) {
                url = String.format("%s://%s%s", siteUri.getScheme(), siteUri.getHost(), siteUri.getPath());
            } else {
                url = String.format("%s://%s:%s%s", siteUri.getScheme(), siteUri.getHost(), siteUri.getPort(),
                        siteUri.getPath());
            }

            log.debug("url:: {}", url);

            // Helper class that handle parameters and form fields.
            ApiList paramList = new ApiList();

            // Process QueryString from url by transferring it to paramList.
            if (null != siteUri.getQuery()) {
                String queryString = siteUri.getRawQuery();
                log.debug("queryString:: {}", queryString);

                String[] paramArr = queryString.split("&");
                for (String item : paramArr) {
                    log.debug("queryItem:: {}", item);
                    String[] itemArr = item.split("=");
                    try {
                        if (itemArr.length == 1) {
                            paramList.add(itemArr[0], "");
                        } else {
                            paramList.add(itemArr[0], java.net.URLDecoder.decode(itemArr[1],
                                    StandardCharsets.UTF_8.toString()));
                        }
                    } catch (UnsupportedEncodingException e) {
                        throw e;
                    }
                }

            }

            // Add the form fields to paramList.
            if (formList != null && formList.size() > 0) {
                paramList.addAll(formList);
            }

            paramList.add(authPrefix + "_timestamp", timestamp);
            paramList.add(authPrefix + "_nonce", nonce);
            paramList.add(authPrefix + "_app_id", appId);
            paramList.add(authPrefix + "_signature_method", signatureMethod);
            paramList.add(authPrefix + "_version", "1.0");

            String baseString = httpMethod.toUpperCase() + "&" + url + "&" + paramList.toString(true);
            log.debug("Exit :: getBaseString :: baseString : {} ", baseString);

            return baseString;
        } catch (ApiUtilException ae) {
            ae.printStackTrace();
            log.error("Error :: getBaseString :: " + ae.getMessage(), ae);
            throw ae;
        } catch (Exception e) {
            e.printStackTrace();
            log.error("Error :: getBaseString :: " + e.getMessage());
            throw new ApiUtilException("Error while getting Base String", e);
        }
    }

    /**
     * Get Signature Token for HTTP Authorization Header
     *
     * @param realm      Identifier for message that comes from the realm for your app
     * @param authPrefix Authorization Header scheme prefix , i.e 'prefix_appId'
     * @param httpMethod API Service URL
     * @param urlPath    API Service endpoint
     * @param appId      App's ID
     * @param secret     App's Secret
     * @param formList   Form Data
     * @param password   Keystore's password
     * @param alias      Keystore's Alias
     * @param fileName   Private Keystore Filepath
     * @param nonce      Random Nonce, Optional
     * @param timestamp  Timestamp , Optional
     * @return
     * @throws ApiUtilException
     */
    public static String getSignatureToken(String realm, String authPrefix, String httpMethod, String urlPath,
                                           String appId, String secret, ApiList formList, String password, String alias,
                                           String fileName, String nonce, String timestamp) throws ApiUtilException {
        log.debug("Enter :: getToken :: realm : {} , authPrefix  : {} , appId : {} , "
                        + "urlPath : {} , httpMethod : {} , nonce : {} , timestamp : {} , secret : {} , password : {}" +
                        " , alias : {} , fileName : {}", realm, authPrefix, appId, urlPath, httpMethod, nonce,
                timestamp, secret, password, alias, fileName);

        try {
            authPrefix = authPrefix.toLowerCase();

            // Generate the nonce value
            nonce = (nonce != null && !nonce.isEmpty()) ? nonce : getNewNonce();
            timestamp = timestamp != null ? timestamp : Long.toString(getNewTimestamp());

            String signatureMethod;

            if (authPrefix.toLowerCase().contains("l1")) {
                signatureMethod = "HMACSHA256";
            } else if (authPrefix.toLowerCase().contains("l2")) {
                signatureMethod = "SHA256withRSA";
            } else {
                throw new ApiUtilException("Invalid Authorization Prefix.");
            }

            String baseString = getBaseString(authPrefix, signatureMethod, appId, urlPath, httpMethod, formList, nonce,
                    timestamp);

            String base64Token = "";

            if ("HMACSHA256".equals(signatureMethod)) {
                base64Token = getHMACSignature(baseString, secret);
            } else if ("SHA256withRSA".equals(signatureMethod)) {
                PrivateKey privateKey = null;
                if (null != fileName && (fileName.contains(".key") || fileName.contains(".pem"))) {
                    privateKey = ApiSigning.getPrivateKeyPEM(fileName, password);
                } else {
                    //For JKS file
                    privateKey = ApiSigning.getPrivateKeyFromKeyStore(fileName, password, alias);
                }

                //PrivateKey privateKey = getPrivateKeyFromKeyStore(fileName, password, alias);
                base64Token = getRSASignature(baseString, privateKey);

            }

            ApiList tokenList = new ApiList();

            tokenList.add("realm", realm);
            tokenList.add(authPrefix + "_app_id", appId);
            tokenList.add(authPrefix + "_nonce", nonce);
            tokenList.add(authPrefix + "_signature_method", signatureMethod);
            tokenList.add(authPrefix + "_timestamp", timestamp);
            tokenList.add(authPrefix + "_version", "1.0");
            tokenList.add(authPrefix + "_signature", base64Token);

            String authorizationToken = String.format("%s %s",
                    authPrefix.substring(0, 1).toUpperCase() + authPrefix.substring(1), tokenList.toString(", ",
                            false, true, false));
            log.debug("Exit :: getToken :: authorizationToken : {} ", authorizationToken);

            return authorizationToken;
        } catch (ApiUtilException ae) {
            log.error("Error :: getToken :: " + ae.getMessage());
            throw ae;
        } catch (Exception e) {
            log.error("Error :: getToken :: " + e.getMessage());
            throw new ApiUtilException("Error while getting Token", e);
        }
    }

    private static long getNewTimestamp() {
        return System.currentTimeMillis();
    }

    /**
     * Get new Nonce value used for signature generation
     *
     * @return nonce value
     * @throws NoSuchAlgorithmException
     */
    private static String getNewNonce() throws NoSuchAlgorithmException {
        byte[] b = new byte[32];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }

    /**
     * Get Private Key from PEM format file
     *
     * @param privateKeyFileName PEM file path
     * @param password
     * @return Private Key
     * @throws IOException
     */
    public static PrivateKey getPrivateKeyPEM(String privateKeyFileName, String password) throws IOException {
        log.debug("Enter :: getPrivateKeyPEM :: privateKeyFileName : {} ", privateKeyFileName);

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Private key file in PEM format.
        File privateKeyFile = new File(privateKeyFileName);

        // Try with resources which will auto close the parser.
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile))) {
            Object object = pemParser.readObject();
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            KeyPair kp;
            if (object instanceof PEMEncryptedKeyPair) {
                kp = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
            } else {
                kp = converter.getKeyPair(((PEMKeyPair) object));
            }
            PrivateKey key = kp.getPrivate();
            log.debug("Exit :: getPrivateKeyPEM");

            return key;
        }
    }
}
