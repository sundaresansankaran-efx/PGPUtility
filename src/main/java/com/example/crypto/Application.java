package com.example.crypto;

import com.example.crypto.properties.PgpProperty;
import com.example.crypto.service.ICryptoService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application implements CommandLineRunner {

	@Autowired
	private ICryptoService cryptoService;

	@Autowired
	private PgpProperty pgpProperty;

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		System.out.println("-----Starting PGP utility Service----------");

		String action = System.getProperty("action");
		String inputPath = System.getProperty("input");
		String outputPath = System.getProperty("output");

		if(StringUtils.isNotBlank(action) && StringUtils.isNotBlank(inputPath) && StringUtils.isNotBlank(outputPath)){
			String publicKeyPath = System.getProperty("publicKey");
			String privateKeyPath = System.getProperty("privateKey");
			String profile = System.getProperty("profile");

			if(StringUtils.isNotBlank(profile)){
				publicKeyPath = String.format("%s\\%s\\PublicKey.txt",pgpProperty.getResourcePath(),profile);
				privateKeyPath = String.format("%s\\%s\\PrivateKey.txt",pgpProperty.getResourcePath(),profile);
			}

			if(StringUtils.isNotBlank(publicKeyPath) && action.equalsIgnoreCase("encrypt")){
				System.out.println("-----Starting PGP Encryption----------");
				boolean result = cryptoService.encryptFile(inputPath,outputPath,publicKeyPath);
				System.out.println("Completed PGP Encryption, Status : "+result);
			}else if(StringUtils.isNotBlank(privateKeyPath) && action.equalsIgnoreCase("decrypt")){
				System.out.println("-----Starting PGP Decryption----------");
				boolean result =cryptoService.decryptFile(inputPath,outputPath,privateKeyPath);
				System.out.println("Completed PGP Decryption, Status : "+result);
			}else if(!StringUtils.isNotBlank(publicKeyPath) && action.equalsIgnoreCase("encrypt")){
				System.out.println("Need publicKey or profile need to encrypt");
			}else if(!StringUtils.isNotBlank(privateKeyPath) && action.equalsIgnoreCase("decrypt")){
				System.out.println("Need privateKey or profile need to decrypt");
			}else{
				System.out.println("Invalid action, Nedd proper action name(encrypt or decrypt)");
			}
		}else{
			System.out.println("Mandatory arguments (action,input,output) are missing");
		}
		System.out.println("---End---");
	}



}
