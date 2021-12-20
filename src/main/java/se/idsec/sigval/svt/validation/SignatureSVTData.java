/*
 * Copyright (c) 2019-2021 Sweden Connect
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
