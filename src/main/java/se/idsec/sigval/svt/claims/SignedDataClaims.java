package se.idsec.sigval.svt.claims;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignedDataClaims {
  private String ref;
  private String hash;
}
