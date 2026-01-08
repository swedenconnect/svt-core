/*
 * Copyright 2019-2025 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.sigval.svt.enums;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * @author stefan
 */
public class SignerKeyStore {

  private final File ksFile;
  private final char[] password;
  private KeyStore ks;
  private KsType kstype;
  private boolean initialized;
  private X509Certificate signerCert;
  private List<X509Certificate> chain;
  private String keyAlias;

  public SignerKeyStore(String ksFileLocation, String password) {
    this.ksFile = getFileFromLocation(ksFileLocation);
    this.password = getPassword(password);
    this.kstype = getKsType();
    try {
      initKs();
    }
    catch (Exception ex) {
      initialized = false;
    }
    if (!initialized) {
      System.out.println("Error: unable to initialize key source");
    }
  }

  private char[] getPassword(String password) {
    return password.toCharArray();
  }

  public boolean isInitialized() {
    return initialized;
  }

  private void initKs() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
    CertificateEncodingException, UnrecoverableKeyException {

    switch (kstype) {
    case JKS:
      ks = KeyStore.getInstance("JKS");
      break;
    case P12:
      ks = KeyStore.getInstance("PKCS12");
      break;
    default:
      initialized = false;
      return;

    }
    ks.load(new FileInputStream(ksFile), password);
    getCertsAndKeyAlias();
    if (signerCert == null || chain.size() < 1) {
      initialized = false;
    }
    //System.out.println("initalized Key Sorce. CertPath length = " + String.valueOf(chain.size()));
    initialized = true;
  }

  private KsType getKsType() {
    if (ksFile == null) {
      return KsType.UNKNOWN;
    }
    String name = ksFile.getName();
    if (name.endsWith("12") || name.endsWith("pfx")) {
      return KsType.P12;
    }
    return KsType.JKS;
  }

  private void getCertsAndKeyAlias() throws KeyStoreException, CertificateEncodingException, CertificateException, IOException,
    NoSuchAlgorithmException, UnrecoverableKeyException {
    List<X509Certificate> unorderedlist = new ArrayList<X509Certificate>();
    Enumeration<String> aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      X509Certificate cert = getCertificate(ks.getCertificate(alias).getEncoded());
      boolean eeCert = isEECert(cert);
      if (eeCert) {
        if (ks.getKey(alias, password) != null) {
          keyAlias = alias;
          signerCert = cert;
        }
      }
      unorderedlist.add(cert);
    }
    if (signerCert == null || unorderedlist.isEmpty()) {
      return;
    }
    List<X509Certificate> orderedCertList = getOrderedCertList(unorderedlist, signerCert);
    chain = orderedCertList;
  }

  public PrivateKey getPrivate() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
    return (PrivateKey) ks.getKey(keyAlias, password);
  }

  public X509Certificate getSignerCert() {
    return signerCert;
  }

  public List<X509Certificate> getChain() {
    return chain;
  }

  public X509Certificate[] getChainArray() {
    return chain.toArray(new X509Certificate[chain.size()]);
  }

  public static File getFileFromLocation(String resourceLocation) {
    if (resourceLocation.toLowerCase().startsWith("classpath:")){
      return new File(SignerKeyStore.class.getResource("/" + resourceLocation.substring(10)).getFile());
    }
    return new File(resourceLocation);
  }

  public static List<X509Certificate> getOrderedCertList(List<X509Certificate> unorderedpdfSignCerts, X509Certificate signerCert) {
    List<X509Certificate> orderedCertList = new ArrayList<X509Certificate>();

    for (X509Certificate cert : unorderedpdfSignCerts) {
      if (cert.equals(signerCert)) {
        orderedCertList.add(signerCert);
        break;
      }
    }

    if (orderedCertList.isEmpty()) {
      return orderedCertList;
    }

    if (isSelfSigned(signerCert)) {
      return orderedCertList;
    }

    boolean noParent = false;
    boolean selfSigned = false;
    X509Certificate target = signerCert;

    while (!noParent && !selfSigned) {
      for (X509Certificate cert : unorderedpdfSignCerts) {
        try {
          target.verify(cert.getPublicKey());
          orderedCertList.add(cert);
          target = cert;
          noParent = false;
          selfSigned = isSelfSigned(cert);
          break;
        } catch (Exception e) {
          noParent = true;
        }
      }

    }
    return orderedCertList;

  }

  public static boolean isSelfSigned(X509Certificate cert) {
    try {
      cert.verify(cert.getPublicKey());
      return true;
    } catch (Exception e) {
    }
    return false;
  }

  public static boolean isEECert(X509Certificate cert) {
    return cert.getBasicConstraints() == -1;
  }

  public static X509Certificate getEECert(List<X509Certificate> certList) {
    for (X509Certificate cert : certList) {
      if (isEECert(cert)) {
        return cert;
      }
    }
    return null;
  }

  public static X509Certificate getCertificate(byte[] certBytes) throws CertificateException, IOException {
    InputStream inStream = null;
    try {
      inStream = new ByteArrayInputStream(certBytes);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(inStream);
    } finally {
      if (inStream != null) {
        inStream.close();
      }
    }
  }

  public enum KsType {
    JKS,P12,UNKNOWN;
  }


}
