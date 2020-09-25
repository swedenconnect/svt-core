package se.idsec.sigval.svt.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.sigval.svt.claims.SVTClaims;
import se.idsec.sigval.svt.claims.SignatureClaims;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignatureSVTValidationResult {
  /** True if the SVT is valid and matches the signed document and the assigned signature. This is not an indication that the signature was successfully
   * validated in the past. This is determined by the policy validation results carried in the {@link SignatureClaims} object */
  private boolean svtValidationSuccess;
  /** A message providing human readable information about the result */
  private String message;
  /** The signature claims for this signature obtained from the signed JWT */
  private SignatureClaims signatureClaims;
  /** The certificate chain used by the SVT issuer when validating this signature, including the signature certificate */
  private List<byte[]> certificateChain;
  /** The certificate used byt the SVT issuer when validating this signature representing the signer */
  private byte[] signerCertificate;
  /** Signed and verified SVT for this signature holding a trusted SVT token. */
  private SignedJWT signedJWT;
}
