package signature;

import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.implementations.RSAKeyValueResolver;
import org.apache.xml.security.keys.keyresolver.implementations.X509CertificateResolver;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class VerifySignature {
	
	public static Document loadDocument() {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(new File("./data/results.xml"));

			return document;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
public static boolean verifySignature(Document doc,Certificate cer) {
		
		try { 
			NodeList signatures = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			Element signatureEl = (Element) signatures.item(0);
			
			XMLSignature signature = new XMLSignature(signatureEl, null);
			
			KeyInfo keyInfo = signature.getKeyInfo();
			
			if(keyInfo != null) {
				keyInfo.registerInternalKeyResolver(new RSAKeyValueResolver());
			    keyInfo.registerInternalKeyResolver(new X509CertificateResolver());
			    
			    if(keyInfo.containsX509Data() && keyInfo.itemX509Data(0).containsCertificate()) { 
			        Certificate cert = keyInfo.itemX509Data(0).itemCertificate(0).getX509Certificate();
			        
			        if(cert != null) 
			        	return signature.checkSignatureValue((X509Certificate) cert);
			        else
			        	return false;
			    }
			    else
			    	return false;
			}
			else
				return false;
		
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} 
	}

}
