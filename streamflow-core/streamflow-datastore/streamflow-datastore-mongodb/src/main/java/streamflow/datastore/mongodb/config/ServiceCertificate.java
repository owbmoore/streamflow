package streamflow.datastore.mongodb.config;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.ConfigurationException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class ServiceCertificate {
    private final static Logger log = LoggerFactory.getLogger(ServiceCertificate.class);

    private final String certificate;
    private final String certificateChain;
    private final String privateKey;
    private final String passphrase;
    private SSLContext sslContext;

    public ServiceCertificate(String certificate, String certificateChain, String privateKey, String passphrase) {
        this.certificate = certificate;
        this.certificateChain = certificateChain;
        this.privateKey = privateKey;
        this.passphrase = passphrase;
    }

    public synchronized SSLContext getSSLContext() {
        if (sslContext == null) {
            sslContext = buildSSLContext();
        }

        return sslContext;
    }

    private SSLContext buildSSLContext() {
        try {
            KeyStore keyStore = buildKeyStore();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, passphrase.toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

            return sslContext;
        } catch (Exception e) {
            log.error("Failed to initialize SSL Context: {}", e.getMessage(), e);
            throw new RuntimeException("Cannot Initialize SSL Context", e);
        }
    }

    private KeyStore buildKeyStore() throws ConfigurationException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            Certificate ca = loadCertificate(certificateChain);

            keyStore.setCertificateEntry("1", ca);

            Certificate clientCertificate = loadCertificate(certificate);
            PrivateKey privateKey = loadPrivateKey();

            keyStore.setCertificateEntry("client-cert", clientCertificate);
            keyStore.setKeyEntry("client-key", privateKey, passphrase.toCharArray(),
                    new Certificate[]{clientCertificate});

            return keyStore;
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Cannot build keystore", e);
        }
    }

    private PrivateKey loadPrivateKey()
            throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        try (PEMParser pemParser = new PEMParser(new StringReader(privateKey))) {
            final Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            // Encrypted key - we will use provided password
            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .build(passphrase.toCharArray());
                PrivateKeyInfo keyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(provider);
                return converter.getPrivateKey(keyInfo);
            } else {
                KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
                return kp.getPrivate();
            }
        } catch (Exception e) {
            log.error("Failed to decrypt private key: {}", e.getMessage(), e);
            throw new GeneralSecurityException("Not supported format of a private key");
        }
    }

    private Certificate loadCertificate(String certificatePem) throws IOException, GeneralSecurityException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        final byte[] content = readPemContent(certificatePem);

        Certificate res = null;
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(content)) {
            res = certificateFactory.generateCertificate(inputStream);
        }
        return res;
    }

    private byte[] readPemContent(String pem) throws IOException {
        final byte[] content;
        try (PemReader pemReader = new PemReader(new StringReader(pem))) {
            final PemObject pemObject = pemReader.readPemObject();
            content = pemObject.getContent();
        }
        return content;
    }
}

