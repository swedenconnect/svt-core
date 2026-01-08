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
package se.swedenconnect.sigval.svt;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.sigval.svt.claims.CertReferenceClaims;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.SVTProfile;
import se.swedenconnect.sigval.svt.claims.SigReferenceClaims;
import se.swedenconnect.sigval.svt.claims.SignatureClaims;
import se.swedenconnect.sigval.svt.claims.SignedDataClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;
import se.swedenconnect.sigval.svt.enums.SignerKeyStore;
import se.swedenconnect.sigval.svt.enums.TestData;
import se.swedenconnect.sigval.svt.issuer.SVTIssuer;
import se.swedenconnect.sigval.svt.issuer.SVTModel;

import static org.junit.jupiter.api.Assertions.*;

public class SVTIssuanceTests {

  private static TestData testData;

  @BeforeAll
  public static void init() throws IOException {
    Security.addProvider(new BouncyCastleProvider());
    testData = new TestData();
  }

  @Test
  public void testSvtIssuance() throws Exception {

    InputStream propIs = getClass().getResourceAsStream("/ks.properties");
    Properties prop = new Properties();
    prop.load(propIs);

    SignerKeyStore ecc521KeyStore = new SignerKeyStore(prop.getProperty("keystore.ec521.location"),
      prop.getProperty("keystore.ec521.password"));
    SignerKeyStore rsaKeyStore = new SignerKeyStore(prop.getProperty("keystore.rsa.location"), prop.getProperty("keystore.rsa.password"));

    SVTModel[] model = new SVTModel[] {
      SVTModel.builder()
        .svtIssuerId("https://example.com/svt-issuer")
        .validityPeriod(Long.valueOf("31708800000"))
        .audience(Arrays.asList("http://example.com/audience1"))
        .certRef(true)
        .build(),
      SVTModel.builder()
        .svtIssuerId("https://example.com/svt-issuer")
        .audience(Arrays.asList("http://example.com/audience1"))
        .build()
    };


    SVTIssuer<?>[] svtIssuer = new SVTIssuer[] {
      new SVTSigValClaimsIssuer(JWSAlgorithm.RS256, rsaKeyStore.getPrivate(), rsaKeyStore.getChain()),
      new SVTSigValClaimsIssuer(JWSAlgorithm.PS384, rsaKeyStore.getPrivate(), rsaKeyStore.getChain()),
      new SVTSigValClaimsIssuer(JWSAlgorithm.PS512, rsaKeyStore.getPrivate(), rsaKeyStore.getChain()),
      new SVTSigValClaimsIssuer(JWSAlgorithm.ES512, ecc521KeyStore.getPrivate(), ecc521KeyStore.getChain()),
      new SVTSigValClaimsIssuer(JWSAlgorithm.ES256, ecc521KeyStore.getPrivate(), ecc521KeyStore.getChain()),
    };

    //Model fail test
    try {
      new SVTSigValClaimsIssuer(JWSAlgorithm.HS256, ecc521KeyStore.getPrivate(), ecc521KeyStore.getChain());
      fail("Unsupported algorithm");
    }
    catch (Exception ignored) {
    }

    //Perform tests
    performTest(svtIssuer[0], model[0], 0);
    performTest(svtIssuer[0], model[0], 1);
    performTest(svtIssuer[1], model[0], 2);
    performTest(svtIssuer[2], model[0], 3);
    performTest(svtIssuer[3], model[1], 4);
    performTest(svtIssuer[4], model[1], 5);
  }

  @SuppressWarnings({ "unchecked", "rawtypes" })
  private void performTest(SVTIssuer svtIssuer, SVTModel model, int idx) throws Exception {

    try {
      SignedJWT signedSvtJWT = svtIssuer.getSignedSvtJWT(new byte[] {}, model);

      String headerJson = signedSvtJWT.getHeader().toString();
      JWTClaimsSet jwtClaimsSet = signedSvtJWT.getJWTClaimsSet();
      String jwtid = jwtClaimsSet.getJWTID();
      BigInteger jtiInt = new BigInteger(jwtid, 16);
      assertTrue(jtiInt.bitLength() > 120, "JWT ID is to short");

      Date issueTime = jwtClaimsSet.getIssueTime();
      Date expirationTime = jwtClaimsSet.getExpirationTime();
      //Test issue time
      assertTrue(issueTime.after(new Date(System.currentTimeMillis() - 10000)), "Issue time is too soon");
      assertTrue(issueTime.before(new Date(System.currentTimeMillis() + 10000)), "Issue time is too late");
      if (expirationTime != null) {
        Calendar validTo = Calendar.getInstance();
        validTo.add(Calendar.YEAR, 1);
        assertTrue(expirationTime.after(validTo.getTime()), "Expiration time is too soon");
        validTo.add(Calendar.MONTH, 1);
        assertTrue(expirationTime.before(validTo.getTime()), "Expiration time is too late");
      }

      String iatStr = String.valueOf(issueTime.getTime() / 1000);
      String expStr = expirationTime == null ? "NULL" : String.valueOf(expirationTime.getTime() / 1000);

      String claimsJson = jwtClaimsSet.toString();

      switch (idx) {
      case 0:
        JSONAssert.assertEquals(testData.getJsonHeader0(), headerJson, true);
        JSONAssert.assertEquals(testData.getJsonClaims0()
            .replace("###JWTID###", jwtid)
            .replace("###IAT###", iatStr)
            .replace("###EXP###", expStr)
          , claimsJson, true);
        break;
      case 2:
        JSONAssert.assertEquals(testData.getJsonHeader2(), headerJson, true);
        JSONAssert.assertEquals(testData.getJsonClaims2()
            .replace("###JWTID###", jwtid)
            .replace("###IAT###", iatStr)
            .replace("###EXP###", expStr)
          , claimsJson, true);
        break;
      case 3:
        JSONAssert.assertEquals(testData.getJsonHeader3(), headerJson, true);
        JSONAssert.assertEquals(testData.getJsonClaims3()
            .replace("###JWTID###", jwtid)
            .replace("###IAT###", iatStr)
            .replace("###EXP###", expStr)
          , claimsJson, true);
        break;
      case 4:
        JSONAssert.assertEquals(testData.getJsonHeader4(), headerJson, true);
        JSONAssert.assertEquals(testData.getJsonClaims4()
            .replace("###JWTID###", jwtid)
            .replace("###IAT###", iatStr)
            .replace("###EXP###", expStr)
          , claimsJson, true);
        break;
      default:
        fail("The present test case should have failed with a thrown exception");
      }

    }
    catch (Exception ex) {
      switch (idx) {
      case 1:
      case 5:
        // This was an expected exception
        break;
      default:
        fail("The present test case resulted in an unexpected exception: " + ex.getMessage());
      }
    }
    Logger.getLogger(SVTIssuanceTests.class.getName()).info("Passed SVT test " + idx);
  }

  private static class SVTSigValClaimsIssuer extends SVTIssuer<byte[]> {

    static List<SignatureClaims> claimsDataList;
    static List<SVTProfile> svtProfiles;
    static int sigCounter = 0;
    static int profileCounter = 0;

    static {
      claimsDataList = getClaimsData();
      svtProfiles = Arrays.asList(SVTProfile.XML, SVTProfile.XML, SVTProfile.XML, SVTProfile.PDF);
    }

    public SVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey, List<X509Certificate> certificates)
      throws Exception {
      super(algorithm, privateKey, certificates);
    }

    @Override public List<SignatureClaims> verify(byte[] signedDocument, String hashAlgoUri) throws Exception {
      try {
        return Arrays.asList(claimsDataList.get(sigCounter++));
      } catch (Exception ex) {
        return Arrays.asList(claimsDataList.get(claimsDataList.size() -1));
      }
    }

    @Override public SVTProfile getSvtProfile() {
      try {
        return svtProfiles.get(profileCounter++);
      } catch (Exception ex) {
        return svtProfiles.get(svtProfiles.size()-1);
      }
    }

    private static List<SignatureClaims> getClaimsData() {
      String certHash = "NSuFM/vJ+beBlQtQTzmcYh5x7L8WC9E1KPHRA1ioNOlKVGbla9URzYcsisAx2bcsqOhkvVTc3mK9E6ag07hfaw==";
      String sbHash = "3GHV73gElWk1yPZRjFtCPtEfEAGRX/kaJWL3I5fm43tkFo3+1FKdqIA6apYFZz7xT2awj/zvWudHa4OyBaP7aA==";
      String sigHash = "Vdypzu0SfeCiB+FNDicTHbq7e8oKKET+1nWgC+jzyZgjmGOfWXi/5/3El0WmnNJfZ65E+eLjkpeA8gWH23UNVw==";
      String sdHash = "Tw3rePgAhYSHtccYJyRRSzSqEIWMKktI5NWJPzf+KJ1CDUDrmHpO9RSKvwdMForF0gYNAvzuUpEYCzJxgKvSaw==";
      String docRef = "0 74697 79699 37908";
      String pol = "http://id.swedenconnect.se/svt/sigval-policy/chain/01";

      SigReferenceClaims sigReferenceClaims = SigReferenceClaims.builder()
        .sb_hash(sbHash)
        .sig_hash(sigHash)
        .build();

      List<PolicyValidationClaims> policyValidationClaims = Arrays.asList(PolicyValidationClaims.builder()
        .pol(pol)
        .msg("Passed basic validation")
        .res(ValidationConclusion.PASSED)
        .build());

      List<SignedDataClaims> signedDataClaims = Arrays.asList(SignedDataClaims.builder()
        .ref(docRef)
        .hash(sdHash)
        .build());

      List<CertReferenceClaims> certReferenceClaimsList = Arrays.asList(CertReferenceClaims.builder()
          .type(CertReferenceClaims.CertRefType.chain_hash.name())
          .ref(Arrays.asList(certHash))
          .build(),
        null,
        CertReferenceClaims.builder()
          .type(CertReferenceClaims.CertRefType.chain_hash.name())
          .ref(Arrays.asList(certHash))
          .build(),
        CertReferenceClaims.builder()
          .type(CertReferenceClaims.CertRefType.chain_hash.name())
          .ref(Arrays.asList(certHash))
          .build());

      List<SignatureClaims> signatureClaimsList = certReferenceClaimsList.stream()
        .map(certReferenceClaims -> SignatureClaims.builder()
          .sig_ref(sigReferenceClaims)
          .sig_data_ref(signedDataClaims)
          .sig_val(policyValidationClaims)
          .time_val(new ArrayList<>())
          .signer_cert_ref(certReferenceClaims)
          .build())
        .collect(Collectors.toList());

      return signatureClaimsList;
    }
  }

}
