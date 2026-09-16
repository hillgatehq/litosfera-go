import java.io.*;
import java.security.cert.*;
import javax.xml.parsers.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import org.w3c.dom.*;

// Independent XMLDSig verification using the JDK, not the Go canonicalizer.
class Verify {
 public static void main(String[] args) throws Exception {
  DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();
  f.setNamespaceAware(true);
  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
  Document doc=f.newDocumentBuilder().parse(new File(args[0]));
  NodeList all=doc.getElementsByTagName("*");
  for(int i=0;i<all.getLength();i++){Element e=(Element)all.item(i);if(e.hasAttribute("Id"))e.setIdAttribute("Id",true);}
  X509Certificate cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(args[1]));
  Node signature=doc.getElementsByTagNameNS(XMLSignature.XMLNS,"Signature").item(0);
  // Litosfera emits an empty, unreferenced KeyInfo in edoc mode. The JDK
  // rejects that schema quirk. Remove only that empty element; it is inside
  // the enveloped Signature and is not covered by any edoc Reference.
  NodeList kis=doc.getElementsByTagNameNS(XMLSignature.XMLNS,"KeyInfo");
  if(kis.getLength()==1){Element ki=(Element)kis.item(0);if(!ki.hasChildNodes())ki.getParentNode().removeChild(ki);}
  DOMValidateContext ctx=new DOMValidateContext(cert.getPublicKey(),signature);
  XMLSignature sig=XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(ctx);
  boolean good=sig.validate(ctx);
  if(!good){System.err.println("SignatureValue="+sig.getSignatureValue().validate(ctx));for(Object o:sig.getSignedInfo().getReferences()){Reference r=(Reference)o;System.err.println(r.getURI()+"="+r.validate(ctx));}System.exit(1);}
 }
}
