package se.idsec.sigval.svt.enums;

import java.util.Arrays;
import java.util.Optional;

public enum DefaultCertRefType {
  chain, chain_hash, UNKNOWN;

  public static DefaultCertRefType getCertRefType(String type) {
    if (type == null){
      return DefaultCertRefType.UNKNOWN;
    }
    Optional<DefaultCertRefType> typeOptional = Arrays.stream(values())
      .filter(defaultCertRefType -> type.equalsIgnoreCase(defaultCertRefType.name()))
      .findFirst();

    return typeOptional.isPresent() ? typeOptional.get() : DefaultCertRefType.UNKNOWN;
  }

}
