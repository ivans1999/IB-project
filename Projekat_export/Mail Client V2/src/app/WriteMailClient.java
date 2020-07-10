package app;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import util.XmlTransfromator;


public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
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
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			
			//ucitavanje sifre,sertifikata iz keystorea
			KeyStoreReader kStoreReader = new KeyStoreReader();
			kStoreReader.load(new FileInputStream("./data/usera.jks"), "usera");
			Certificate certificateUserB = kStoreReader.getCertificate("userb");
			PublicKey publicKey = certificateUserB.getPublicKey();
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] sifrovanKljuc = rsaCipherEnc.doFinal(secretKey.getEncoded());
			System.out.println("Kriptovan kljuc: " + Base64.encodeToString(sifrovanKljuc));
			
			//KeyStoreReader keyStoreReader = new KeyStoreReader();
			
			KeyStore keyStoreUserA = kStoreReader.readKeyStore("./data/usera.jks", "usera".toCharArray());
			KeyStore keyStoreUserB = kStoreReader.readKeyStore("./data/userb.jks", "userb".toCharArray());
			
			
			PrivateKey privateKey = kStoreReader.getPKey(keyStoreUserA, "usera", "usera".toCharArray());
			
			
			XmlTransfromator.transformXML(reciever,compressedSubject,compressedBody);
			
			Certificate userBCertificate = kStoreReader.getCertificateFromKeyStore(keyStoreUserB, "userb");
			PublicKey publicKeyUserB = kStoreReader.getPublicKeyFromCertificate(userBCertificate);
			
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			cipher.init(Cipher.ENCRYPT_MODE, publicKeyUserB);
			
			MailBody mBody = new MailBody(ciphertextStr, ivParameterSpec1.getIV(), ivParameterSpec2.getIV(), sifrovanKljuc);
			String mailBody = mBody.toCSV();
			System.out.println("Telo emaila: " + mailBody);
			
			
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
}
