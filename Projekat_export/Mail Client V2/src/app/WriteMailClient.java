package app;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.io.InputStreamReader;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import util.KeyStoreReader;
import support.MailHelper;
import support.MailWritter;


public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String KEY_STORE_USER_A = "./data/usera.jks";
	private static final String KEY_STORE_USER_B = "./data/userb.jks";
	private static final String KEY_STORE_A_PASSWORD = "usera";
	private static final String KEY_STORE_B_PASSWORD = "usera"; 
	private static final String KEY_STORE_B_ALIAS = "userb";
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			byte [] ivParamSpec1 = ivParameterSpec1.getIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertextBody = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStrBody = Base64.encodeToString(ciphertextBody);
			System.out.println("Crypyed text: " + ciphertextStrBody);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			byte [] ivParamSpec2 = ivParameterSpec2.getIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphertextSubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphertextStrSubject = Base64.encodeToString(ciphertextSubject);
			System.out.println("Crypted subject: " + ciphertextStrSubject);
			
			
			//ucitavanje sifre,sertifikata iz keystorea
			KeyStore keyStoreUserA = keyStoreReader.readKeyStore(KEY_STORE_USER_B, KEY_STORE_B_PASSWORD.toCharArray());
			Certificate certificateB = keyStoreReader.getCertificateFromKeyStore(keyStoreUserA, KEY_STORE_B_ALIAS);
			PublicKey publicKeyUserB = keyStoreReader.getPublicKeyFromCertificate(certificateB);
			PrivateKey privateKeyUserB = keyStoreReader.getPrivateKeyFromKeyStore(keyStoreUserA, KEY_STORE_B_ALIAS, KEY_STORE_B_PASSWORD.toCharArray());
			System.out.println("UserB certificate: " + certificateB);
			System.out.println("UserB public key:  " + publicKeyUserB);
			
			//sifrovanje session-key uz pomoc javnog kljuca
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, publicKeyUserB);
			byte[] ciphertextSessionKey = rsaCipherEnc.doFinal(secretKey.getEncoded());
			
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
			//potpis 
		       Signature signature = Signature.getInstance("SHA256withRSA");
		       signature.initSign(privateKeyUserB);
		       byte[] bytes = ciphertextBody;
		       signature.update(bytes);
		      byte[] sign = signature.sign();
		      System.out.println("Email has been signed with signature : ");
		      System.out.println(sign.toString());
			  MailBody mailBody = new MailBody(ciphertextBody, ivParamSpec1, ivParamSpec2,  ciphertextSessionKey, sign);
			  
     	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphertextStrBody, mailBody.toCSV());
     	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}
