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
package se.swedenconnect.sigval.svt.issuer;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * This is the data model for an SVT issuing request and holds parameters that are not derived from the signature
 * validation process or from the general JWT token parameters (such as selected signing algorithm and hash algorithm).
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SVTModel {

  /**
   * The unique identifier of the SVT issuer.
   *
   * @param svtIssuerId
   *          the SVT issuer ID
   * @return the SVT issuer ID
   */
  private String svtIssuerId;

  /**
   * The validity period of the SVT expressed in milliseconds. A {@code null} value results in an absent expiration
   * date.
   *
   * @param validityPeriod
   *          validity of SVT is milliseconds
   * @return validity of SVT is milliseconds or null
   */
  private Long validityPeriod;

  /**
   * A list of identifiers of intended audiences.
   *
   * @param audience
   *          ID:s for intended audiences
   * @return ID:s for intended audiences
   */
  private List<String> audience;

  /**
   * A value of {@code true} means that the certificates will be referenced by an identifier equal to the hash of the
   * certificate.
   *
   * @param certRef
   *          whether certificates will be referenced using certificate hashes
   * @return whether certificates will be referenced using certificate hashes
   */
  @Builder.Default
  boolean certRef = false;
}
