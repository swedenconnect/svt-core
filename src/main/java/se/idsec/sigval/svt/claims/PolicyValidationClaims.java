package se.idsec.sigval.svt.claims;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyValidationClaims {
  private String pol;
  private ValidationConclusion res;
  private String msg;
  private Map<String, String> ext;

}
