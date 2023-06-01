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

import java.io.IOException;
import java.io.InputStream;

import com.nimbusds.jose.util.IOUtils;

import lombok.Getter;

@Getter
public class TestData {

  private final String jsonClaims0;
  private final String jsonClaims2;
  private final String jsonClaims3;
  private final String jsonClaims4;
  private final String jsonHeader0;
  private final String jsonHeader2;
  private final String jsonHeader3;
  private final String jsonHeader4;

  public TestData() throws IOException {
    jsonClaims0 = getResourceString("json-claims-0");
    jsonClaims2 = getResourceString("json-claims-2");
    jsonClaims3 = getResourceString("json-claims-3");
    jsonClaims4 = getResourceString("json-claims-4");

    jsonHeader0 = getResourceString("json-header-0");
    jsonHeader2 = getResourceString("json-header-2");
    jsonHeader3 = getResourceString("json-header-3");
    jsonHeader4 = getResourceString("json-header-4");

  }

  private String getResourceString(String resourceName) throws IOException {
    InputStream resourceAsStream = getClass().getResourceAsStream("/test-data/" + resourceName + ".json");
    return IOUtils.readInputStreamToString(resourceAsStream);
  }
}

