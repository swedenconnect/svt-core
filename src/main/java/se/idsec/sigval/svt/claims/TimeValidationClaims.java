package se.idsec.sigval.svt.claims;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TimeValidationClaims {
  private long time;
  private String type;
  private String iss;
  private String id;
  private List<PolicyValidationClaims> val;
  private Map<String, String> ext;
}
