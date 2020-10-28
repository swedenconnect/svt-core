/*
 * Copyright (c) 2020 IDsec Solutions AB
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
package se.idsec.sigval.svt.issuer;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.util.encoders.Base64;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.claims.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * This is the main class for issuing an SVT token. Some fields and internal functions are declared as protected to allow extensibility.
 * The primary customization option is to provide a custom SVTSigValClaimsIssuer which implements the relevant SVT profile such as XML
 * or PDF. All functions of this class are profile neutral.
 */
public abstract class SVTIssuer<T extends Object> {

  /** Certificates used to verify the signature on the JWT */
  protected List<X509Certificate> certificates;
  /** The algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values */
  protected JWSAlgorithm jwsAlgorithm;
  /** THe signer used to sign SVT tokens */
  protected JWSSigner signer;

  /**
   *
   * @param algorithm the algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values
   * @param privateKey private key used to sign the SVT
   * @param certificates certificates supporting the SVT signature
   * @throws NoSuchAlgorithmException if the requested algorithm is not supported
   * @throws JOSEException exception processing JOSE data
   */
  public SVTIssuer(JWSAlgorithm algorithm, Object privateKey, List<X509Certificate> certificates)
    throws NoSuchAlgorithmException, JOSEException {
    // Check that the selected algorithm is supported
    if (!SVTAlgoRegistry.isAlgoSupported(algorithm)) {
      throw new NoSuchAlgorithmException("Selected JWT algorithm is not supported");
    }
    this.jwsAlgorithm = algorithm;
    this.signer = SVTAlgoRegistry.getSigner(jwsAlgorithm, privateKey, certificates.get(0).getPublicKey());
    this.certificates = certificates;
  }

  /**
   * Verifies the signed document and generates the SVT claims
   * @param signedDataInput signed data input for the signatures being validated
   * @param hashAlgoUri hash algorithm URI identifier
   * @return a list of {@link SignatureClaims} objects for each validated signature
   * @throws Exception on errors performing signature validation
   */
  protected abstract List<SignatureClaims> verify(T signedDataInput, String hashAlgoUri) throws Exception;

  /**
   * Return the SVT Profile implemented by this SVT issuer implementation
   * @return {@link SVTProfile}
   */
  protected abstract SVTProfile getSvtProfile();

  /**
   * Perform validation of all signatures on a signed document and generate the Signed SVT based on the provided SVTClaimsIssuer
   *
   * @param signedDataInput input data for the signature or signatures being validated
   * @param model model object holding parameters for SVT generation not derived from signature validation
   * @return Signed SVT
   * @throws Exception if creation of the signed SVT fails.
   */
  public SignedJWT getSignedSvtJWT(T signedDataInput, SVTModel model)
    throws Exception {

    List<SignatureClaims> signatureClaims = verify(signedDataInput, SVTAlgoRegistry.getAlgoParams(jwsAlgorithm).getDigestAlgoId());
    if (signatureClaims == null || signatureClaims.isEmpty()){
      // Not returning signature claims is a valid option if the input material did not cause claims to be collected
      // One example of this is if the XML option is set to extend only if a current SVT is not present, and a valid SVT is already present
      return null;
    }
    for (SignatureClaims claims: signatureClaims) {
      validateSignatureSVTClaims(claims);
    }

    // Generate SVT claims
    SVTClaims svtClaims = SVTClaims.builder()
      .ver("1.0")
      .profile(getSvtProfile())
      .hash_algo(SVTAlgoRegistry.getAlgoParams(jwsAlgorithm).getDigestAlgoId())
      .sig(signatureClaims)
      .build();


    // Set default value for embedded certificates and key identifier in the JOSE header
    List<com.nimbusds.jose.util.Base64> certChain = null;
    String kid = null;
    // Set values
    if (certificates.size() > 0) {
      if (model.isCertRef()) {
        MessageDigest svtDigestAlgo = SVTAlgoRegistry.getMessageDigestInstance(jwsAlgorithm);
        kid = Base64.toBase64String(svtDigestAlgo.digest(certificates.get(0).getEncoded()));
      }
      else {
        certChain = new ArrayList<>();
        for (X509Certificate cert : certificates) {
          try {
            certChain.add(new com.nimbusds.jose.util.Base64(Base64.toBase64String(cert.getEncoded())));
          }
          catch (CertificateEncodingException e) {
            throw new IOException("Unsupported hash algorithm in model");
          }
        }
      }
    }

    // Assemble and sign
    SignedJWT signedJWT = new SignedJWT(
      new JWSHeader(
        jwsAlgorithm, JOSEObjectType.JWT, null, null, null, null, null, null, null,
        certChain, kid, null, null
      ),
      getSvtJwtClaims(svtClaims, model)
    );

    signedJWT.sign(signer);
    return signedJWT;
  }

  /**
   * Prepare the complete SWT claims set
   * @param svtClaims claims for the signature validation token
   * @param model model data
   * @return JWT claims set
   */
  public static JWTClaimsSet getSvtJwtClaims(SVTClaims svtClaims, SVTModel model) {

    JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
      .issuer(model.getSvtIssuerId())
      .jwtID(new BigInteger(128, new Random(System.currentTimeMillis())).toString(16))
      .issueTime(new Date())
      .claim("sig_val_claims", svtClaims);

    if (model.getValidityPeriod() != null) {
      builder.expirationTime(new Date(System.currentTimeMillis() + model.getValidityPeriod()));
    }

    List<String> audienceList = model.getAudience();
    if (audienceList != null && !audienceList.isEmpty()) {
      builder.audience(audienceList);
    }

    JWTClaimsSet claimsSet = builder.build();

    return claimsSet;
  }

  /**
   * Function designed to perform a basic check to ensure that a signature claims set contains valid data
   * @param signatureClaims signature claims object
   * @throws IllegalArgumentException returned if invalid data is found
   */
  protected void validateSignatureSVTClaims(SignatureClaims signatureClaims) throws IllegalArgumentException {
    valueTest(signatureClaims.getSigner_cert_ref(), "SVT signature cert reference");

    //Doc hash
    List<SignedDataClaims> doc_hash = signatureClaims.getSig_data_ref();
    valueTest(doc_hash, "Document digest");
    if (doc_hash.size() < 1) {
      throw new IllegalArgumentException("At least one document hash must be present");
    }
    for (SignedDataClaims sigDataClaim : doc_hash){
      valueTest(sigDataClaim.getHash(), "Ref hash value");
      if (sigDataClaim.getRef() == null) throw new IllegalArgumentException("Doc reference must not be null");
    }

    //Sig reference
    valueTest(signatureClaims.getSig_ref().getSb_hash(), "Signature signed data reference");
    valueTest(signatureClaims.getSig_ref().getSig_hash(), "Signature value reference");

    //Sig results
    List<PolicyValidationClaims> validationList = signatureClaims.getSig_val();
    valueTest(validationList, "Signature validation results");
    for (PolicyValidationClaims validation : validationList) {
      valueTest(validation.getRes(), "Signature validation result");
      valueTest(validation.getPol(), "Signature validation policy");
    }
  }

  /**
   * Basic value tests
   * @param o object to be tested
   * @param desc descriptive text for the value test object
   * @throws IllegalArgumentException returned if invalid data is found
   */
  protected void valueTest(Object o, String desc) throws IllegalArgumentException {
    if (o == null) {
      throw new IllegalArgumentException(desc + " has a null value");
    }
    if (o instanceof String && ((String) o).trim().isEmpty()) {
      throw new IllegalArgumentException(desc + " has an empty value");
    }
    if (o instanceof List && ((List<?>) o).isEmpty()) {
      throw new IllegalArgumentException(desc + " has no values");
    }
  }
}

