package com.example.crypto.service;

import java.io.FileNotFoundException;
import org.bouncycastle.openpgp.PGPPublicKey;

public interface ICryptoService {

    PGPPublicKey readPublicKey(String publicKeyPath) throws FileNotFoundException;
    Boolean encryptFile(String inputPath,String outputPath,String publicKeyPath);
    Boolean decryptFile(String inputFileName,String outPutFileName,String privateKeyPath);

}
