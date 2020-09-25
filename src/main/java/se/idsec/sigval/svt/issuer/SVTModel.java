package se.idsec.sigval.svt.issuer;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * This is the data model for an SVT issuing request and holds parameters that are not derived from the signature validation process
 * or from the general JWT token parameters (such as selected signing algorithm and hash algorithm).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SVTModel {
  /** The unique identifier of the SVT issuer */
  private String svtIssuerId;
  /** The validity period of the SVT expressed in milliseconds. A null value results in an absent expiration date */
  private Long validityPeriod;
  /** A list of identifiers of intended audiences */
  private List<String> audience;
  /** A value of true means that the certificates will be referenced by an identifier equal to the hash of the certificate */
  boolean certRef = false;
}
