![Logo](https://raw.githubusercontent.com/swedenconnect/technical-framework/master/img/sweden-connect.png) 

# Signature Validation Token Core

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.idsec.sigval/svt-core/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.idsec.sigval/svt-core)

<!-- 

Use when 1.1.0 is released ...

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.sigval/svt-base/badge.svg)](https://maven-badges.herokuapp.com/maven-central/se.swedenconnect.sigval/svt-base) 

-->

Core components for generation and validation of Signature Validation Tokens (SVT) providing the following core features:

- Java classes representing the claims of SVT tokens.
- Abstract SVT isuer providing core functions for issuing SVT tokens.
- Abstract SVT validator provising core functions for validating signatures based on SVT tokens

**Note**: This library has been moved to the [swedenconnect](https://github.com/swedenconnect) organization from [idsec-solutions](https://github.com/idsec-solutions) where it was named "sig-validation-svt". Artifact and package names have also been changed from `idsec` to `swedenconnect`. During the move, the artifact-id was changed from `svt-base` to `svt-core`.

---

## Maven

From version 1.1.0 and onwards:

```
<dependency>
    <groupId>se.swedenconnect.sigval</groupId>
    <artifactId>svt-core</artifactId>
    <version>${svt-base.version}</version>
</dependency>
```

Older versions:

```
<dependency>
    <groupId>se.idsec.sigval</groupId>
    <artifactId>svt-base</artifactId>
    <version>${svt-base.version}</version>
</dependency>
```

##### API documentation

Java API documentation for [se.swedenconnect.sigval:svt-base](https://docs.swedenconnect.se/svt-core/javadoc).

---

Copyright &copy; [The Swedish Agency for Digital Government (DIGG)](https://www.digg.se), 2019-2021. All Rights Reserved.
