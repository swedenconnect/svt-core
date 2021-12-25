/*
 * Copyright (c) 2019-2021 Sweden Connect
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
package se.swedenconnect.sigval.svt.enums;

public class TestData {

  public static final String JSON_CLAIMS_0 = "{\"aud\":\"http:\\/\\/example.com\\/audience1\",\"iss\":\"https:\\/\\/example.com\\/svt-issuer\","
    + "\"exp\":###EXP###,\"iat\":###IAT###,\"jti\":\"###JWTID###\",\"sig_val_claims\":{\"sig\":[{\"ext\":null,"
    + "\"sig_val\":[{\"msg\":\"Passed basic validation\",\"ext\":null,\"res\":\"PASSED\",\"pol\":\"http:\\/\\/id.swedenconnect.se\\/svt\\/sigval-policy\\/chain\\/01\"}],"
    + "\"sig_ref\":{\"sig_hash\":\"Vdypzu0SfeCiB+FNDicTHbq7e8oKKET+1nWgC+jzyZgjmGOfWXi\\/5\\/3El0WmnNJfZ65E+eLjkpeA8gWH23UNVw==\",\"id\":null,"
    + "\"sb_hash\":\"3GHV73gElWk1yPZRjFtCPtEfEAGRX\\/kaJWL3I5fm43tkFo3+1FKdqIA6apYFZz7xT2awj\\/zvWudHa4OyBaP7aA==\"},"
    + "\"signer_cert_ref\":{\"ref\":[\"NSuFM\\/vJ+beBlQtQTzmcYh5x7L8WC9E1KPHRA1ioNOlKVGbla9URzYcsisAx2bcsqOhkvVTc3mK9E6ag07hfaw==\"],\"type\":\"chain_hash\"},"
    + "\"sig_data_ref\":[{\"ref\":\"0 74697 79699 37908\",\"hash\":\"Tw3rePgAhYSHtccYJyRRSzSqEIWMKktI5NWJPzf+KJ1CDUDrmHpO9RSKvwdMForF0gYNAvzuUpEYCzJxgKvSaw==\"}],"
    + "\"time_val\":[]}],\"ext\":null,\"ver\":\"1.0\",\"profile\":\"XML\",\"hash_algo\":\"http:\\/\\/www.w3.org\\/2001\\/04\\/xmlenc#sha256\"}}";
  public static final String JSON_CLAIMS_2 = "{\"aud\":\"http:\\/\\/example.com\\/audience1\",\"iss\":\"https:\\/\\/example.com\\/svt-issuer\","
    + "\"exp\":###EXP###,\"iat\":###IAT###,\"jti\":\"###JWTID###\",\"sig_val_claims\":{\"sig\":[{\"ext\":null,"
    + "\"sig_val\":[{\"msg\":\"Passed basic validation\",\"ext\":null,\"res\":\"PASSED\",\"pol\":\"http:\\/\\/id.swedenconnect.se\\/svt\\/sigval-policy\\/chain\\/01\"}],"
    + "\"sig_ref\":{\"sig_hash\":\"Vdypzu0SfeCiB+FNDicTHbq7e8oKKET+1nWgC+jzyZgjmGOfWXi\\/5\\/3El0WmnNJfZ65E+eLjkpeA8gWH23UNVw==\",\"id\":null,"
    + "\"sb_hash\":\"3GHV73gElWk1yPZRjFtCPtEfEAGRX\\/kaJWL3I5fm43tkFo3+1FKdqIA6apYFZz7xT2awj\\/zvWudHa4OyBaP7aA==\"},"
    + "\"signer_cert_ref\":{\"ref\":[\"NSuFM\\/vJ+beBlQtQTzmcYh5x7L8WC9E1KPHRA1ioNOlKVGbla9URzYcsisAx2bcsqOhkvVTc3mK9E6ag07hfaw==\"],\"type\":\"chain_hash\"},"
    + "\"sig_data_ref\":[{\"ref\":\"0 74697 79699 37908\",\"hash\":\"Tw3rePgAhYSHtccYJyRRSzSqEIWMKktI5NWJPzf+KJ1CDUDrmHpO9RSKvwdMForF0gYNAvzuUpEYCzJxgKvSaw==\"}],"
    + "\"time_val\":[]}],\"ext\":null,\"ver\":\"1.0\",\"profile\":\"XML\",\"hash_algo\":\"http:\\/\\/www.w3.org\\/2001\\/04\\/xmldsig-more#sha384\"}}";
  public static final String JSON_CLAIMS_3 = "{\"aud\":\"http:\\/\\/example.com\\/audience1\",\"iss\":\"https:\\/\\/example.com\\/svt-issuer\","
    + "\"exp\":###EXP###,\"iat\":###IAT###,\"jti\":\"###JWTID###\",\"sig_val_claims\":{\"sig\":[{\"ext\":null,"
    + "\"sig_val\":[{\"msg\":\"Passed basic validation\",\"ext\":null,\"res\":\"PASSED\",\"pol\":\"http:\\/\\/id.swedenconnect.se\\/svt\\/sigval-policy\\/chain\\/01\"}],"
    + "\"sig_ref\":{\"sig_hash\":\"Vdypzu0SfeCiB+FNDicTHbq7e8oKKET+1nWgC+jzyZgjmGOfWXi\\/5\\/3El0WmnNJfZ65E+eLjkpeA8gWH23UNVw==\",\"id\":null,"
    + "\"sb_hash\":\"3GHV73gElWk1yPZRjFtCPtEfEAGRX\\/kaJWL3I5fm43tkFo3+1FKdqIA6apYFZz7xT2awj\\/zvWudHa4OyBaP7aA==\"},"
    + "\"signer_cert_ref\":{\"ref\":[\"NSuFM\\/vJ+beBlQtQTzmcYh5x7L8WC9E1KPHRA1ioNOlKVGbla9URzYcsisAx2bcsqOhkvVTc3mK9E6ag07hfaw==\"],\"type\":\"chain_hash\"},"
    + "\"sig_data_ref\":[{\"ref\":\"0 74697 79699 37908\",\"hash\":\"Tw3rePgAhYSHtccYJyRRSzSqEIWMKktI5NWJPzf+KJ1CDUDrmHpO9RSKvwdMForF0gYNAvzuUpEYCzJxgKvSaw==\"}],"
    + "\"time_val\":[]}],\"ext\":null,\"ver\":\"1.0\",\"profile\":\"XML\",\"hash_algo\":\"http:\\/\\/www.w3.org\\/2001\\/04\\/xmlenc#sha512\"}}";
  public static final String JSON_CLAIMS_4 = "{\"aud\":\"http:\\/\\/example.com\\/audience1\",\"iss\":\"https:\\/\\/example.com\\/svt-issuer\","
    + "\"iat\":###IAT###,\"jti\":\"###JWTID###\",\"sig_val_claims\":{\"sig\":[{\"ext\":null,"
    + "\"sig_val\":[{\"msg\":\"Passed basic validation\",\"ext\":null,\"res\":\"PASSED\",\"pol\":\"http:\\/\\/id.swedenconnect.se\\/svt\\/sigval-policy\\/chain\\/01\"}],"
    + "\"sig_ref\":{\"sig_hash\":\"Vdypzu0SfeCiB+FNDicTHbq7e8oKKET+1nWgC+jzyZgjmGOfWXi\\/5\\/3El0WmnNJfZ65E+eLjkpeA8gWH23UNVw==\",\"id\":null,"
    + "\"sb_hash\":\"3GHV73gElWk1yPZRjFtCPtEfEAGRX\\/kaJWL3I5fm43tkFo3+1FKdqIA6apYFZz7xT2awj\\/zvWudHa4OyBaP7aA==\"},"
    + "\"signer_cert_ref\":{\"ref\":[\"NSuFM\\/vJ+beBlQtQTzmcYh5x7L8WC9E1KPHRA1ioNOlKVGbla9URzYcsisAx2bcsqOhkvVTc3mK9E6ag07hfaw==\"],\"type\":\"chain_hash\"},"
    + "\"sig_data_ref\":[{\"ref\":\"0 74697 79699 37908\",\"hash\":\"Tw3rePgAhYSHtccYJyRRSzSqEIWMKktI5NWJPzf+KJ1CDUDrmHpO9RSKvwdMForF0gYNAvzuUpEYCzJxgKvSaw==\"}],"
    + "\"time_val\":[]}],\"ext\":null,\"ver\":\"1.0\",\"profile\":\"PDF\",\"hash_algo\":\"http:\\/\\/www.w3.org\\/2001\\/04\\/xmlenc#sha512\"}}";

  public static final String JSON_HEADER_0 = "{\"kid\":\"RWyt9kpS5WPgUD+Dlkyvoff80MgeaSNS7XINA950RV0=\",\"typ\":\"JWT\",\"alg\":\"RS256\"}";
  public static final String JSON_HEADER_2 = "{\"kid\":\"8CXpdadi7sJej6FLSNP04Jp\\/ozra1maTRlILD89sBXK7sFhi4VQ5acBuofY\\/VGy0\",\"typ\":\"JWT\",\"alg\":\"PS384\"}";
  public static final String JSON_HEADER_3 = "{\"kid\":\"NSuFM\\/vJ+beBlQtQTzmcYh5x7L8WC9E1KPHRA1ioNOlKVGbla9URzYcsisAx2bcsqOhkvVTc3mK9E6ag07hfaw==\",\"typ\":\"JWT\",\"alg\":\"PS512\"}";
  public static final String JSON_HEADER_4 = "{\"x5c\":[\"MIIB6TCCAUugAwIBAgIEXHAXuDAKBggqhkjOPQQDAjA5MQswCQYDVQQGEwJTRTEOMAwGA1UECgwFSURzZW"
    + "MxGjAYBgNVBAMMEU9wZW5TQU1MIEVDQyBUZXN0MB4XDTE5MDIyMjE1MzkzNloXDTIwMDIyMjE1MzkzNlowOTELMAkGA1UEBhMCU0UxDjAMBgNVBAoMBUlEc2VjMRowGAYDVQQD"
    + "DBFPcGVuU0FNTCBFQ0MgVGVzdDCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAZwDANVSXP5eNwOV98Z9aqzN\\/wHZAUi8ajuc0pSm0lII5vAMpSEvkybTzSWEd\\/dRDPuRbn"
    + "G1qwuRxDzBIqWocHG6AG0cldhLVCl4vV3T89PUAL9dGRb18uWnwTUOYbu9c8ZyuE79YOwfjIJsqKA\\/PBccpi2Dg3519o6S2IywxWNHNPwKMAoGCCqGSM49BAMCA4GLADCBhw"
    + "JCANcQxmeQ4n8zY2lqrtjho9MQKmbYuOzoWz5Jo\\/4d+9OORZ0U9Q0z8D+IEtKT4ddDfoUL0b0oCGOV7O0xc3jzLlANAkE8k4vV087cb4Z6KX2QtNEHf1qYoyEyb5QKYnu8kj"
    + "FkvFkhQ7Vq3GDQF3dGkL26FEaSL0g6CvpYGzb3e\\/cqWozF5g==\"],\"typ\":\"JWT\",\"alg\":\"ES512\"}";
}
