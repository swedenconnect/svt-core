package se.idsec.sigval.svt.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.claims.CertReferenceClaims;
import se.idsec.sigval.svt.claims.SigReferenceClaims;
import se.idsec.sigval.svt.claims.SignatureClaims;
import se.idsec.sigval.svt.claims.SignedDataClaims;
import se.idsec.sigval.svt.enums.DefaultCertRefType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Getter
@NoArgsConstructor
public abstract class SVTValidator<T extends Object> {

  /**
   * Extract relevant data from the signature necessary to validate its consistency with a SVT record.
   *
   * @return a list of {@link SignatureSVTData} object. One for each signature to validate.
   */
  protected abstract List<SignatureSVTData> getSignatureSVTData(T signedDataInput) throws Exception;

  /**
   * Override this method to implement custom signature validation
   *
   * @param signatureSVTData
   * @param hashAlgorithm
   * @throws RuntimeException
   */
  public void customSignatureSVTValidation(SignatureSVTData signatureSVTData, String hashAlgorithm, SignatureSVTValidationResult result)
    throws RuntimeException {
  }

  /**
   * Override this method to handle certificate reference types other than the default types.
   * This method is only invoked if the reference type is unknown.
   * The override method must write the resulting certificates to the result object. The default behaviour is to fail validation if a
   * custom reference type is encounteredF
   *
   * @param svtCertRef   Certificate reference data from the SVT
   * @param sigCertChain Certificates obtained from the signature in the order they appear in the signature
   * @return true if certificates match
   */
  protected boolean customCertificateRefCheck(CertReferenceClaims svtCertRef, List<byte[]> sigCertChain,
    SignatureSVTValidationResult result) {
    return false;
  }

  /**
   * The main validation method. Validates all SVT records and store the results.
   */
  public List<SignatureSVTValidationResult> validate(T signedDataInput) {
    List<SignatureSVTValidationResult> results = new ArrayList<>();

    /**
     * Validation process:
     * - Identify the signature and the data that relates to it
     * - Verify hashed data:
     *    - Signature context and signature value
     *    - Signed document references
     *    - Certificate chain
     *    - Signing certificate
     */

    List<SignatureSVTData> signatureSVTDataList = null;
    try {
      signatureSVTDataList = getSignatureSVTData(signedDataInput);
    }
    catch (Exception e) {
      log.debug("Error parsing XML SVT data {}", e.getMessage());
      return results;
    }

    if (signatureSVTDataList == null || signatureSVTDataList.isEmpty()) {
      return results;
    }

    // Process the signatures
    for (SignatureSVTData sigData : signatureSVTDataList) {
      SignatureSVTValidationResult result = new SignatureSVTValidationResult();
      SignatureClaims svtSigClaims = sigData.getSignatureClaims();
      SignedJWT signedJWT = sigData.getSignedJWT();
      JWSAlgorithm svtJwsAlgo = signedJWT.getHeader().getAlgorithm();

      // Check signature identification and context data
      if (!compareSignatureIdentification(svtSigClaims.getSig_ref(), sigData.getSignatureReference())) {
        results.add(new SignatureSVTValidationResult(
          false, "The signature of the target document does not match the SVT record.",
          svtSigClaims, null, null, signedJWT));
        continue;
      }

      // Check signed document references
      if (!compareDocumentReferenceData(svtSigClaims.getSig_data_ref(), sigData.getSignedDataRefList())) {
        results.add(new SignatureSVTValidationResult(
          false, "The target signed document does not match the SVT record.",
          svtSigClaims, null, null, signedJWT));
        continue;
      }

      // Check certificates
      if (!certificateConsistencyCheck(svtSigClaims.getSigner_cert_ref(), sigData.getSignerCertChain(), result, svtJwsAlgo)) {
        result.setSvtValidationSuccess(false);
        result.setSignatureClaims(svtSigClaims);
        result.setSignedJWT(signedJWT);
        if (result.getMessage() == null) {
          result.setMessage("Signer certificates does not match the provided SVT certificate references");
        }
        results.add(result);
        continue;
      }

      try {
        customSignatureSVTValidation(sigData, SVTAlgoRegistry.getAlgoParams(svtJwsAlgo).getDigestAlgoId(), result);
      }
      catch (Exception ex) {
        result.setSvtValidationSuccess(false);
        if (result.getMessage() == null) {
          result.setMessage(ex.getMessage());
        }
        results.add(result);
        continue;
      }

      //Reaching this point meas that the signature validation was successful for this signature
      result.setSvtValidationSuccess(true);
      result.setSignatureClaims(svtSigClaims);
      result.setMessage("OK");
      result.setSignedJWT(signedJWT);
      results.add(result);

    }
    return results;
  }

  /**
   * Checks that the SVT signature reference data matches the target signature
   *
   * @param svtSigRef signature reference data from the SVT
   * @param sigRef    signature reference data from the target signature
   * @return true on data match
   */
  private boolean compareSignatureIdentification(SigReferenceClaims svtSigRef, SigReferenceClaims sigRef) {
    if (!svtSigRef.getSig_hash().equals(sigRef.getSig_hash())) {
      return false;
    }
    if (!svtSigRef.getSb_hash().equals(sigRef.getSb_hash())) {
      return false;
    }
    return true;
  }

  /**
   * Checks that the target signed document matches the SVT signed data references
   *
   * @param svtSigDataRefList The SVT signed data reference list
   * @param sigDataRefList    the signed document signed data reference list
   * @return true on data match
   */
  private boolean compareDocumentReferenceData(List<SignedDataClaims> svtSigDataRefList, List<SignedDataClaims> sigDataRefList) {

    // Loop through all SVT references and make sure there is a matching reference in the signed document
    for (SignedDataClaims svtSigDataRef : svtSigDataRefList) {
      // Look for a matching record
      boolean match = sigDataRefList.stream()
        .filter(signedDataClaims -> signedDataClaims.getHash().equals(svtSigDataRef.getHash()))
        .filter(signedDataClaims -> signedDataClaims.getRef().equals(svtSigDataRef.getRef()))
        .findFirst().isPresent();
      if (!match) {
        // This signed data reference does not match the signed document.
        return false;
      }
    }
    return true;
  }

  /**
   * Checks that the signer certificate chain in the SVT matches the signed document. The SVT issuer may have used an entirely different set
   * of certificates to verify the signature than the set provided with the signature. This may be a result of using for example a national
   * TSL (Trust service Status List) to select a trusted trust anchor rather than a trust anchor provided with the signature.
   * This process therfore use the following logic:
   * <ul>
   *   <li>If the SVT contains a full chain, then this chain will be stored in the result as the evaluated chain with no further checks.</li>
   *   <li>If the SVT contains cert hash and chain hash, then these must match the certificates from the signed document</li>
   * </ul>
   *
   * @param svtCertRef         the certificate reference data from the SVT
   * @param signatureCertChain the certificates provided with the signature
   * @param result             the result object where any message is stored
   * @return true if certificates match
   */
  private boolean certificateConsistencyCheck(CertReferenceClaims svtCertRef, List<byte[]> signatureCertChain,
    SignatureSVTValidationResult result, JWSAlgorithm jwsAlgorithm) {

    DefaultCertRefType refType = DefaultCertRefType.getCertRefType(svtCertRef.getType());
    List<String> certRefList = svtCertRef.getRef();

    switch (refType) {
    case chain:
      try {
        List<byte[]> chain = certRefList.stream()
          .map(s -> Base64.decode(s))
          .collect(Collectors.toList());
        result.setCertificateChain(chain);
        // The signer certificate MUST be the first certificate in the list according to the SVT specification
        result.setSignerCertificate(chain.get(0));
        return true;
      }
      catch (Exception ex) {
        result.setMessage("Failed to obtain valid certificate reference information of type 'cert'");
        return false;
      }
    case chain_hash:
      /*
      Process is to first check the signer certificate hash. If this is the only hash, then store this cert also as the chain.
      If a chain is present, then check the chain.
       */
      try {
        String certHash = certRefList.get(0);
        Optional<byte[]> sigCertBytesOptional = signatureCertChain.stream()
          .filter(bytes -> matchHashString(Arrays.asList(bytes), certHash, jwsAlgorithm))
          .findFirst();

        if (!sigCertBytesOptional.isPresent()) {
          result.setMessage("The signer certificate does not match the provided cert hash");
          return false;
        }
        result.setSignerCertificate(sigCertBytesOptional.get());

        if (certRefList.size() < 2) {
          // This is the only cert hash. Store this as the chain and exit
          result.setCertificateChain(Arrays.asList(result.getSignerCertificate()));
          return true;
        }

        // There is also a chain hash. Check the chain and store chain certs
        String chainHash = certRefList.get(1);
        if (!matchHashString(signatureCertChain, chainHash, jwsAlgorithm)) {
          // Signer chain mismatch
          result.setMessage("The signer certificate chain does not match the provided chain hash");
          return false;
        }
        // Chain hash match. Store results
        result.setCertificateChain(signatureCertChain);
        return true;

      }
      catch (Exception ex) {
        result.setMessage("Certificate matching caused exception: " + ex.getMessage());
        return false;
      }
    default:
      // Unknown ref type. Perform the custom validation procedures
      return customCertificateRefCheck(svtCertRef, signatureCertChain, result);
    }
  }

  private boolean matchHashString(List<byte[]> byteList, String b64MatchString, JWSAlgorithm jwsAlgorithm) {
    try {
      MessageDigest messageDigest = SVTAlgoRegistry.getMessageDigestInstance(jwsAlgorithm);
      byteList.stream().forEach(bytes -> messageDigest.update(bytes));
      String byteHashStr = Base64.toBase64String(messageDigest.digest());
      return byteHashStr.equals(b64MatchString);
    }
    catch (NoSuchAlgorithmException e) {
      return false;
    }
  }

}
