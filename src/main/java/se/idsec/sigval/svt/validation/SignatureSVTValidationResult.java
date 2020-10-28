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
package se.idsec.sigval.svt.validation;

import java.util.List;

import com.nimbusds.jwt.SignedJWT;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.sigval.svt.claims.SignatureClaims;

/**
 * Representation of a Signature SVT validation result.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SignatureSVTValidationResult {

  /**
   * Is {@code true} if the SVT is valid and matches the signed document and the assigned signature. This is not an
   * indication that the signature was successfully validated in the past. This is determined by the policy validation
   * results carried in the {@link SignatureClaims} object.
   * 
   * @param svtValidationSuccess SVT validation success flag
   * @return SVT validation success flag
   */
  private boolean svtValidationSuccess;

  /**
   * A message providing human readable information about the result.
   * 
   * @param message textual representation of the result
   * @return textual representation of the result
   */
  private String message;

  /**
   * The signature claims for this signature obtained from the signed JWT.
   * 
   * @param signatureClaims the signature claims
   * @return the signature claims
   */
  private SignatureClaims signatureClaims;

  /**
   * The certificate chain used by the SVT issuer when validating this signature, including the signature certificate.
   * 
   * @param certificateChain the certificate chain
   * @return the certificate chain
   */
  private List<byte[]> certificateChain;

  /**
   * The certificate used by the SVT issuer when validating this signature representing the signer.
   * 
   * @param signerCertificate the signer certificate
   * @return the signer certificate
   */
  private byte[] signerCertificate;

  /**
   * Signed and verified SVT for this signature holding a trusted SVT token.
   * 
   * @param signedJWT the signed SVT
   * @return the signed SVT
   */
  private SignedJWT signedJWT;
}
