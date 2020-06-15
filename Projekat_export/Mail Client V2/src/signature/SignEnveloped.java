package signature;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SignEnveloped {
	
	private Document loadDocument(String file) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(new File(file));

			return document;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	private void saveDocument(Document doc, String fileName) {
		try {
			File outFile = new File(fileName);
			FileOutputStream f = new FileOutputStream(outFile);

			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();
			
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(f);
			
			transformer.transform(source, result);

			f.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private Certificate readCertificate() {
		try {
			KeyStore kStoreReader = KeyStore.getInstance("JKS", "SUN");
			
			BufferedInputStream in = new BufferedInputStream(new FileInputStream("./data/usera.jks"));
			kStoreReader.load(in, "usera".toCharArray());
			
			if(kStoreReader.isKeyEntry("usera")) {
				Certificate cert = kStoreReader.getCertificate("usera");
				return cert;
				
			}
			else
				return null;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	private PrivateKey readPrivateKey() {
		try {
			KeyStore kStoreReader = KeyStore.getInstance("JKS", "SUN");
			
			BufferedInputStream in = new BufferedInputStream(new FileInputStream("./data/usera.jks"));
			kStoreReader.load(in, "usera".toCharArray());
			
			if(kStoreReader.isKeyEntry("usera")) {
				PrivateKey pk = (PrivateKey) kStoreReader.getKey("usera", "usera".toCharArray());
				return pk;
			}
			else
				return null;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private Document signDocument(Document doc, PrivateKey privateKey, Certificate cert) {
	      
	      try {
				Element rootEl = doc.getDocumentElement();
				
				XMLSignature sig = new XMLSignature(doc, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
				
				Transforms transforms = new Transforms(doc);
				    
				transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
				
				transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
				    
				sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
				    
				sig.addKeyInfo(cert.getPublicKey());
				sig.addKeyInfo((X509Certificate) cert);
				    
				rootEl.appendChild(sig.getElement());
				
				sig.sign(privateKey);
				
				return doc;
				
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}

}
