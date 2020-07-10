package util;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import util.KeyStoreReader;

public class XmlTransfromator {
	static {
	  	
	      Security.addProvider(new BouncyCastleProvider());
	      org.apache.xml.security.Init.init();
	  }
	
	public static void transformXML(String recivier, String subject, String body) {
		
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.newDocument();
			
			Element rootElement = doc.createElement("root");
			doc.appendChild(rootElement);
			
			Element message = doc.createElement("message");
			rootElement.appendChild(message);
			
			Element messageRecipient = doc.createElement("recipient");
			messageRecipient.appendChild(doc.createTextNode(recivier));
			message.appendChild(messageRecipient);
			
			Element messageSubject = doc.createElement("subject");
			messageSubject.appendChild(doc.createTextNode(subject));
			message.appendChild(messageSubject);
			
			Element messageBody = doc.createElement("body");
			messageBody.appendChild(doc.createTextNode(body));
			message.appendChild(messageBody);
			
			KeyStoreReader keyStoreReader = new KeyStoreReader();
			
			KeyStore keyStoreUserA = keyStoreReader.readKeyStore("./data/usera.jks", "usera".toCharArray());
			
			PrivateKey privateKeyUserA = keyStoreReader.getPKey(keyStoreUserA, "usera", "usera".toCharArray());
			
			Certificate userAcertificate = keyStoreReader.getCertificateFromKeyStore(keyStoreUserA, "usera");
			
			XMLSignature sig = new XMLSignature(doc,  null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
			
			Transforms transforms = new Transforms(doc);
		
			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS);
			
		
			sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
			
	
			sig.addKeyInfo(userAcertificate.getPublicKey());
			sig.addKeyInfo((X509Certificate) userAcertificate);
			
			rootElement.appendChild(sig.getElement());
			
			sig.sign(privateKeyUserA);	
			System.out.println(".. potpisano");
			
			
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File("./data/results.xml"));
			transformer.transform(source, result);
			
			
			
		}catch(Exception ex) {ex.printStackTrace();}
	}

}
