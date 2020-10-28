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
package se.idsec.sigval.svt.claims;

import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Representation of SVT claims.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SVTClaims {

  /**
   * The version of the claim.
   * 
   * @param ver
   *          the version
   * @return the version
   */
  @Builder.Default
  private String ver = "1.0";

  /**
   * The SVT profile.
   * 
   * @param profile
   *          the SVT profile
   * @return the SVT profile
   */
  private SVTProfile profile;

  /**
   * The hash algorithm.
   * 
   * @param hash_algo
   *          the hash algorithm
   * @return the hash algorithm
   */
  private String hash_algo;

  /**
   * The signature claims.
   * 
   * @param sig
   *          the signature claims
   * @return the signature claims
   */
  private List<SignatureClaims> sig;

  /**
   * Extensions.
   * 
   * @param ext
   *          extensions
   * @return extensions
   */
  private Map<String, String> ext;
}
