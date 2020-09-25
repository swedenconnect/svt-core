package se.idsec.sigval.svt.claims;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertReferenceClaims {
  private String type;
  private List<String> ref;

  public static enum CertRefType {
    chain, chain_hash;
  }

}
