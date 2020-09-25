package se.idsec.sigval.svt.validation;

import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.sigval.svt.claims.SigReferenceClaims;
import se.idsec.sigval.svt.claims.SignatureClaims;
import se.idsec.sigval.svt.claims.SignedDataClaims;

import java.util.List;

/**
 * Class holding data captured from a signature that is to be verified using an SVT token
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignatureSVTData {
  /** Signature reference obtained from the target signature */
  private SigReferenceClaims signatureReference;
  /** List of references to signed data obtained from the target signature and verified against the real signed document */
  private List<SignedDataClaims> signedDataRefList;
  /** The bytes of signer certificate and supporting chain certificates provided with the signed document */
  private List<byte[]> signerCertChain;
  /** The signature claims for this signature obtained from the signed JWT */
  private SignatureClaims signatureClaims;
  /** Signed and verified SVT for this signature holding a trusted SVT token. */
  private SignedJWT signedJWT;
}
