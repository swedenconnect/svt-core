![Logo](https://github.com/idsec-solutions/idsec-solutions.github.io/blob/master/img/idsec.png)

# Signature Validatioin Token

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Core components for generation and validation of Signature Validation Tokens (SVT) providing the following core features:

- Java classes representing the claims of SVT tokens.
- Abstract SVT isuer providing core functions for issueing SVT tokens.
- Abstract SVT validator provising core functions for validating signatures based on SVT tokens

---

## Maven

This project is currently not deployed at maven central. The source code must be built locally and then imported to your project as:

```
<dependency>
    <groupId>se.idsec.sigval</groupId>
    <artifactId>svt-base</artifactId>
    <version>${svt-base.version}</version>
</dependency>

```

##### API documentation

Java API documentation for [se.idsec.sigval:svt-base](https://idsec-solutions.github.io/sig-validation-svt/javadoc).

---

Copyright &copy; 2019-2020, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
