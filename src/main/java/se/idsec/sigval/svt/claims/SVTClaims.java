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
public class SVTClaims {
  private String ver = "1.0";
  private SVTProfile profile;
  private String hash_algo;
  private List<SignatureClaims> sig;
  private Map<String, String> ext;
}
