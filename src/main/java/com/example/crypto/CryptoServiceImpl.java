package com.example.crypto;

import com.example.crypto.properties.PgpProperty;
import com.example.crypto.service.ICryptoService;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;

@RequiredArgsConstructor

public class CryptoServiceImpl implements ICryptoService {

    private final PgpProperty pgpProperty;

    @Override
    public PGPPublicKey readPublicKey(String publicKeyPath) {
        PGPPublicKey publicKey = null;
        try {
            InputStream inputStream = new FileInputStream(publicKeyPath);

            inputStream = PGPUtil.getDecoderStream(inputStream);
            PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(inputStream);
            Iterator<PGPPublicKeyRing> keyRings = keyRingCollection.getKeyRings();
            while (publicKey == null && keyRings.hasNext()) {

                PGPPublicKeyRing kRing = keyRings.next();
                Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();

                while (publicKey == null && kIt.hasNext()) {
                    PGPPublicKey k = kIt.next();

                    if (k.isEncryptionKey()) {
                        publicKey = k;
                    }
                }
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }

        return publicKey;
    }

    @Override
    public Boolean encryptFile(String inputPath, String outPutPath, String publicKeyPath) {
        Boolean encryptSucess = false;
        OutputStream outputStream = null;
        try {
            PGPPublicKey publicKey = readPublicKey(publicKeyPath);
            Security.addProvider(new BouncyCastleProvider());
            outputStream = new FileOutputStream(outPutPath);
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);
            PGPUtil.writeFileToLiteralData(comData.open(bOut),
                PGPLiteralData.BINARY, new File(inputPath));
            comData.close();
            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, true,
                new SecureRandom(), "BC");
            cPk.addMethod(publicKey);
            byte[] bytes = bOut.toByteArray();
            OutputStream cOut = cPk.open(outputStream, bytes.length);
            cOut.write(bytes);
            cOut.close();
            outputStream.close();
            encryptSucess = true;
        } catch (Exception ex) {
            System.out.println(ex);
        } finally {
        }
        return encryptSucess;
    }

    @Override
    public Boolean decryptFile(String inputFolder, String outputFolder, String privateKeyPath) {
        Boolean encryptionStatus = false;
        try {
            Security.addProvider(new BouncyCastleProvider());

            File files = new File(inputFolder);
            if (files.isDirectory()) {
                for (File file : files.listFiles()) {
                    Path path = Paths.get(file.getAbsolutePath());
                    System.out.println("Path of the filename"+ path);
                    if (!file.isDirectory() && Files.probeContentType(path)
                        .equalsIgnoreCase("application/x-zip-compressed")) {
                        try {
                            System.out.println(" Absolute path of zip file " + file.getAbsolutePath());
                            InputStream inputStream = new FileInputStream(file.getAbsolutePath());
                            OutputStream outputStream = new FileOutputStream(outputFolder + "/" + file.getName());

                            inputStream = PGPUtil.getDecoderStream(inputStream);

                            PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(inputStream);
                            Object object = pgpObjectFactory.nextObject();
                            PGPEncryptedDataList encryptedDataList;

                            if (object instanceof PGPEncryptedDataList) {
                                encryptedDataList = (PGPEncryptedDataList) object;
                            } else {
                                encryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
                            }

                            Iterator<PGPPublicKeyEncryptedData> it = encryptedDataList.getEncryptedDataObjects();
                            PGPPrivateKey sKey = null;
                            PGPPublicKeyEncryptedData pbe = null;

                            while (sKey == null && it.hasNext()) {
                                pbe = it.next();
                                sKey = findPrivateKey(pbe.getKeyID(), privateKeyPath);
                            }
                            if (sKey == null) {
                                throw new IllegalArgumentException("Secret key for message not found.");
                            }
                            InputStream clear = pbe.getDataStream(sKey, "BC");
                            PGPObjectFactory plainFact = new PGPObjectFactory(clear);
                            Object message = plainFact.nextObject();

                            if (message instanceof PGPCompressedData) {
                                PGPCompressedData cData = (PGPCompressedData) message;
                                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
                                message = pgpFact.nextObject();
                            }

                            if (message instanceof PGPLiteralData) {
                                PGPLiteralData ld = (PGPLiteralData) message;
                                InputStream unc = ld.getInputStream();
                                int ch;
                                while ((ch = unc.read()) >= 0) {
                                    outputStream.write(ch);
                                }
                            } else if (message instanceof PGPOnePassSignatureList) {
                                throw new PGPException(
                                    "Encrypted message contains a signed message - not literal data.");
                            } else {
                                throw new PGPException("Message is not a simple encrypted file - type unknown.");
                            }
                            if (pbe.isIntegrityProtected()) {
                                if (!pbe.verify()) {
                                    throw new PGPException("Message failed integrity check");
                                }
                            }
                            encryptionStatus = true;
                        } catch (Exception exception) {
                            System.out.println(" decryption failed for the file " + file.getName() + exception);
                        }
                    } else {
                        System.out.println(" Please provide directory to input path ");
                    }
                }
            } else {
                System.out.println(" input path is not a directory");
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return encryptionStatus;
    }

    private PGPPrivateKey findPrivateKey(long keyID, String privateKeyPath) {
        PGPPrivateKey privateKey = null;
        char[] pass = new char[1];
        pass[0] = ' ';
        try {
            InputStream inputStream = new FileInputStream(privateKeyPath);
            inputStream = PGPUtil.getDecoderStream(inputStream);
            PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(inputStream);
            PGPSecretKey secretKey = keyRingCollection.getSecretKey(keyID);
            if (secretKey == null) {
                return null;
            }
            privateKey = secretKey.extractPrivateKey(pgpProperty.getPassphrase().toCharArray(), "BC");
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return privateKey;
    }
}
