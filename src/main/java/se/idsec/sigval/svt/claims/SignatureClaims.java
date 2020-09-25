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
public class SignatureClaims {
  private SigReferenceClaims sig_ref;
  private List<SignedDataClaims> sig_data_ref;
  private CertReferenceClaims signer_cert_ref;
  private List<TimeValidationClaims> time_val;
  private List<PolicyValidationClaims> sig_val;
  private Map<String, String> ext;
}
