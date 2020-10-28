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
