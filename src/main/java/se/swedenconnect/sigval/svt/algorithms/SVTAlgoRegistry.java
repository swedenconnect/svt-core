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
package se.swedenconnect.sigval.svt.algorithms;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Registry for SVT supported algorithms. This class adds support for the minimum supported set of algorithms and allows
 * new algorithms to be added. By default only RSA and ECDSA with SHA 245, 384 and 512 are supported.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SVTAlgoRegistry {
  @Getter
  private static Map<JWSAlgorithm, AlgoProperties> supportedAlgoMap;
  private static List<JWSAlgorithm.Family> supportedAlgoTypes = Arrays.asList(JWSAlgorithm.Family.RSA, JWSAlgorithm.Family.EC);
  private static Map<String, String> supportedDigestAlgoMap;

  public static final String DIGEST_ALGO_NAME_SHA256 = "SHA-256";
  public static final String DIGEST_ALGO_NAME_SHA384 = "SHA-384";
  public static final String DIGEST_ALGO_NAME_SHA512 = "SHA-512";
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
  public static final String ALGO_ID_SIGNATURE_ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA384_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";
  public static final String ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";
  public static final String ALGO_ID_DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
  public static final String ALGO_ID_DIGEST_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
  public static final String ALGO_ID_DIGEST_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
  public static final String ALGO_ID_DIGEST_SHA3_256 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
  public static final String ALGO_ID_DIGEST_SHA3_384 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
  public static final String ALGO_ID_DIGEST_SHA3_512 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

  static {
    supportedAlgoMap = new HashMap<>();
    putDefaultAlgo(JWSAlgorithm.RS256, ALGO_ID_SIGNATURE_RSA_SHA256, ALGO_ID_DIGEST_SHA256, DIGEST_ALGO_NAME_SHA256);
    putDefaultAlgo(JWSAlgorithm.RS384, ALGO_ID_SIGNATURE_RSA_SHA384, ALGO_ID_DIGEST_SHA384, DIGEST_ALGO_NAME_SHA384);
    putDefaultAlgo(JWSAlgorithm.RS512, ALGO_ID_SIGNATURE_RSA_SHA512, ALGO_ID_DIGEST_SHA512, DIGEST_ALGO_NAME_SHA512);
    putDefaultAlgo(JWSAlgorithm.PS256, ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, ALGO_ID_DIGEST_SHA256, DIGEST_ALGO_NAME_SHA256);
    putDefaultAlgo(JWSAlgorithm.PS384, ALGO_ID_SIGNATURE_RSA_SHA384_MGF1, ALGO_ID_DIGEST_SHA384, DIGEST_ALGO_NAME_SHA384);
    putDefaultAlgo(JWSAlgorithm.PS512, ALGO_ID_SIGNATURE_RSA_SHA512_MGF1, ALGO_ID_DIGEST_SHA512, DIGEST_ALGO_NAME_SHA512);
    putDefaultAlgo(JWSAlgorithm.ES256, ALGO_ID_SIGNATURE_ECDSA_SHA256, ALGO_ID_DIGEST_SHA256, DIGEST_ALGO_NAME_SHA256);
    putDefaultAlgo(JWSAlgorithm.ES384, ALGO_ID_SIGNATURE_ECDSA_SHA384, ALGO_ID_DIGEST_SHA384, DIGEST_ALGO_NAME_SHA384);
    putDefaultAlgo(JWSAlgorithm.ES512, ALGO_ID_SIGNATURE_ECDSA_SHA512, ALGO_ID_DIGEST_SHA512, DIGEST_ALGO_NAME_SHA512);
    initalizeAlgoMap();
  }

  private static void initalizeAlgoMap() {
    supportedDigestAlgoMap = new HashMap<>();
    supportedAlgoMap.keySet().stream().forEach(jwsAlgorithm -> {
      AlgoProperties algoProperties = supportedAlgoMap.get(jwsAlgorithm);
      supportedDigestAlgoMap.put(algoProperties.digestAlgoId, algoProperties.getDigestInstanceName());
    });
  }

  /**
   * Test if a particular JWSAlgorithm is supported
   *
   * @param algorithm
   *          algorithm to test
   * @return true if supported
   */
  public static boolean isAlgoSupported(JWSAlgorithm algorithm) {
    return supportedAlgoMap.containsKey(algorithm);
  }

  /**
   * Returns the algorithm parameters for a supported algorithm
   *
   * @param supportedJWSAlgo
   *          algorithm
   * @return algorithm parameters
   * @throws IllegalArgumentException
   *           if the algorithm is not supported
   */
  public static AlgoProperties getAlgoParams(JWSAlgorithm supportedJWSAlgo) throws IllegalArgumentException {
    if (!isAlgoSupported(supportedJWSAlgo)) {
      throw new IllegalArgumentException("Unsupported JWS Algorithm");
    }
    return supportedAlgoMap.get(supportedJWSAlgo);
  }

  /**
   * Get an instance of the message digest algorithm associated with the specified JWS algorithm
   *
   * @param supportedJWSAlgo
   *          JWS algorithm
   * @return {@link MessageDigest} instance
   * @throws NoSuchAlgorithmException
   *           if specified JWS algorithm is not supported
   */
  public static MessageDigest getMessageDigestInstance(JWSAlgorithm supportedJWSAlgo)
      throws NoSuchAlgorithmException {
    if (!isAlgoSupported(supportedJWSAlgo)) {
      throw new NoSuchAlgorithmException("Unsupported JWS Algorithm");
    }
    return MessageDigest.getInstance(supportedAlgoMap.get(supportedJWSAlgo).getDigestInstanceName());
  }

  /**
   * Get an instance of the supported message digest algorithm associated with the specified algorithm identifier
   *
   * @param digestAlgoId
   *          Digest algorithm URI identifier
   * @return {@link MessageDigest} instance
   * @throws NoSuchAlgorithmException
   *           if specified JWS algorithm is not supported
   */
  public static MessageDigest getMessageDigestInstance(String digestAlgoId)
      throws NoSuchAlgorithmException {
    if (!supportedDigestAlgoMap.containsKey(digestAlgoId)) {
      throw new NoSuchAlgorithmException("Unsupported digest algorithm");
    }
    return MessageDigest.getInstance(supportedDigestAlgoMap.get(digestAlgoId));
  }

  /**
   * Register a new supported JWS algorithm family
   *
   * @param family
   *          Famliy to register
   * @return true if the new algorithm was registered
   */
  public static boolean registerSupportedJWSAlgorithmType(JWSAlgorithm.Family family) {
    if (supportedAlgoTypes.contains(family)) {
      return false;
    }
    supportedAlgoTypes.add(family);
    return true;
  }

  /**
   * Register a new supported JWS algorithm for signing the SVT
   *
   * @param algorithm
   *          The JWSAlgorithm object for this algorithm
   * @param sigAlgoId
   *          XML URI identifier for this algorithm
   * @param digestAlgoId
   *          the XML URI identifier for this algorithm
   * @param digestInstanceName
   *          the name of the digest algorithm passed to the supported crypto provider when creating an instance of this
   *          hash algorithm
   * @return true if the algorithm registration was successful
   */
  public static boolean registerSupportedJWSAlgorithm(JWSAlgorithm algorithm, String sigAlgoId, String digestAlgoId,
      String digestInstanceName) throws IllegalArgumentException {
    putDefaultAlgo(algorithm, sigAlgoId, digestAlgoId, digestInstanceName);
    initalizeAlgoMap();
    return true;
  }

  /**
   * Retrieve the algorithm family for a specific JWS algorithm
   *
   * @param algo
   *          the JWS algorithm
   * @return {@link JWSAlgorithm.Family}
   * @throws IllegalArgumentException
   *           if the requested algorithm is not supported
   */
  public static JWSAlgorithm.Family getAlgoFamilyFromAlgo(JWSAlgorithm algo) throws IllegalArgumentException {
    JWSAlgorithm.Family type = null;
    for (JWSAlgorithm.Family fam : supportedAlgoTypes) {
      if (fam.contains(algo)) {
        type = fam;
        break;
      }
    }
    if (type == null) {
      throw new IllegalArgumentException("Unsupported JWS Algorithm family");
    }
    return type;
  }

  /**
   * Creates a signer for a specific algorithm and private key object
   *
   * @param jwsAlgorithm
   *          the JWS algorithm
   * @param privateKey
   *          the suitable private key object for this algorithm type
   * @param publicKey
   *          the public key associated with the private signing key
   * @return {@link JWSSigner}
   * @throws IllegalArgumentException
   *           if the provided parameters are not supported
   * @throws JOSEException
   *           on error
   */
  public static JWSSigner getSigner(JWSAlgorithm jwsAlgorithm, Object privateKey, PublicKey publicKey) throws IllegalArgumentException,
      JOSEException {
    JWSAlgorithm.Family type = getAlgoFamilyFromAlgo(jwsAlgorithm);
    if (type.equals(JWSAlgorithm.Family.EC) &&
        privateKey instanceof PrivateKey &&
        "EC".equalsIgnoreCase(((PrivateKey) privateKey).getAlgorithm()) &&
        publicKey instanceof ECPublicKey) {
      return new ECDSASigner((PrivateKey) privateKey, Curve.forECParameterSpec(((ECPublicKey) publicKey).getParams()));
    }

    if (type.equals(JWSAlgorithm.Family.ED) && privateKey instanceof OctetKeyPair) {
      return new Ed25519Signer((OctetKeyPair) privateKey);
    }
    if (type.equals(JWSAlgorithm.Family.RSA) && privateKey instanceof PrivateKey && "RSA".equalsIgnoreCase(((PrivateKey) privateKey)
      .getAlgorithm())) {
      return new RSASSASigner((PrivateKey) privateKey);
    }
    throw new IllegalArgumentException("Unsupported algorithm and key combination");
  }

  private SVTAlgoRegistry() {
  }

  private static void putDefaultAlgo(JWSAlgorithm algo, String sigAlgoId, String digestAlgoId, String digestInstanceName)
      throws IllegalArgumentException {
    JWSAlgorithm.Family algoType = getAlgoFamilyFromAlgo(algo);
    supportedAlgoMap.put(algo, new AlgoProperties(algoType, sigAlgoId, digestAlgoId, digestInstanceName));
  }

  /**
   * Data object for signature algorithm properties
   */
  @Getter
  @AllArgsConstructor
  public static class AlgoProperties {
    /** The family type of this algorithm */
    JWSAlgorithm.Family type;
    /** XML UIR identifier for the signature algorithm */
    String sigAlgoId;
    /** The XML URI identifier for this algorithm */
    String digestAlgoId;
    /**
     * The name of the digest algorithm passed to the supported crypto provider when creating an instance of this hash
     * algorithm
     */
    String digestInstanceName;
  }

}
