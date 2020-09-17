package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import util.KeyStoreReader;
import model.keystore.IssuerData;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	// validacija
	public static boolean validate(PublicKey publicKey,
			 byte[] data, byte[] sign) throws Exception {
		       Signature signature = Signature.getInstance("SHA256withRSA");
		       signature.initVerify(publicKey);
		       signature.update(data);
		       boolean verified = signature.verify(sign);
		       if (verified==true) {
		    	   System.out.println("Validity of email has been proved with signature.");
		       }else {
		    	   System.out.println("This email is not valid and it's not compatible signature.");
		       }
		        return verified;
		}	

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEY_STORE_USER_B = "./data/userb.jks";
	private static final String KEY_STORE_B_PASSWORD = "userb";
	private static final char [] keyB_password_char = KEY_STORE_B_PASSWORD.toCharArray();
	private static final String KEY_STORE_B_ALIAS = "userb";
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();


	public static void main(String[] args) throws Exception {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
		MimeMessage chosenMessage = mimeMessages.get(answer);
		
		String body = MailHelper.getText(chosenMessage);
		
		//mail body objekat
		MailBody mailBody = new MailBody(body);
		
		//preuzimanje vektora, enkriptovanog kljuca i tela poruke
		IvParameterSpec ivParameterSpec1_test = new IvParameterSpec(mailBody.getIV1Bytes());
		IvParameterSpec ivParameterSpec2_test = new IvParameterSpec(mailBody.getIV2Bytes());
		byte [] message = mailBody.getEncMessageBytes();
		byte [] encSessionKey = mailBody.getEncKeyBytes();	
		byte [] signature = mailBody.getSignatureBytes();
		
		//pristup keystore-u i uzimanje privatnog kljuca korisnika B
		KeyStore keyStoreUserB = keyStoreReader.readKeyStore(KEY_STORE_USER_B, KEY_STORE_B_PASSWORD.toCharArray());
		PrivateKey privateKeyUserB = keyStoreReader.getPrivateKeyFromKeyStore(keyStoreUserB, KEY_STORE_B_ALIAS, keyB_password_char);
		Certificate certificateB = keyStoreReader.getCertificateFromKeyStore(keyStoreUserB, KEY_STORE_B_ALIAS);
		PublicKey publicKeyUserB = keyStoreReader.getPublicKeyFromCertificate(certificateB);

		//dekripcija tajnog kljuca privatnim kljucem korisnika B
		Cipher rsaCipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKeyUserB);
		byte[] sessionKeyDec = rsaCipherDec.doFinal(encSessionKey);
		
		SecretKey ss = new SecretKeySpec(sessionKeyDec, "AES");
		
		//inicijalizacija i dekripcija tela poruke tajnim kljucem
		Cipher bodyCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		bodyCipherDec.init(Cipher.DECRYPT_MODE, ss, ivParameterSpec1_test);
		byte[] receivedTxt = bodyCipherDec.doFinal(message);
		
		//dekompresija tela poruke
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(new String(receivedTxt)));
		
		//dekriptovanje i dekompresija subject-a
		bodyCipherDec.init(Cipher.DECRYPT_MODE, ss, ivParameterSpec2_test);
		String decryptedSubjectTxt = new String(bodyCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));

		validate(publicKeyUserB, message, signature);
		System.out.println("Subject: " + decompressedSubjectTxt);
		System.out.println("Body: " + decompressedBodyText);

	}
	
}