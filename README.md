openmrs-contrib-keycloak-smart-auth
===================================

A Keycloak plugin implementing the OAuth2 extensions that the
[SMART App Launch Framework](https://hl7.org/fhir/smart-app-launch/) adds, so Keycloak can act as the
authorization server for SMART applications reading an OpenMRS FHIR API.

This is the authorization-server half. The FHIR half is
[openmrs-module-smartonfhir](https://github.com/openmrs/openmrs-module-smartonfhir), and neither works
without the other.

## What it provides

| Provider id | What it does |
|---|---|
| `smart-audience-validator` | Enforces the `aud` parameter SMART 2.x requires, naming the FHIR server an app intends to call. Without it a token minted for one FHIR server can be replayed against another on the same realm. |
| `smart-access-authenticator` | Carries an EHR launch: hands the browser to OpenMRS to identify the clinician already signed in there, and accepts the signed token it returns in place of a password. |
| `smart-application-authenticator` | Carries a standalone launch: sends the clinician to OpenMRS to choose a patient, and brings the choice back into the flow. |
| `smart-username-password-form` | Keycloak's login form re-registered under its own id, so it can sit as an `ALTERNATIVE` in a flow. The built-in cannot. |
| `smart-context-claim-mapper` | Puts the chosen patient or encounter in the token response, where SMART 2.x says launch context belongs. |

## Building and installing

Requires **Keycloak 26.7.1**, Java 17 to build and 21 to run.

```bash
mvn clean install
cp keycloak-smart-auth/target/keycloak-smart-auth-*.jar $KEYCLOAK_HOME/providers/
$KEYCLOAK_HOME/bin/kc.sh build
```

The Keycloak version is pinned, not floated: every SPI here is one Keycloak marks internal, logging
`KC-SERVICES0047` for each, so an upgrade can break this plugin with no compiler warning.

## The JAR alone does nothing

Nothing here registers itself into an authentication flow, so a provider Keycloak has loaded but never
invokes is invisible. The wiring — flow, client, scopes, mappers — lives in a realm, and the realm is
**not in this repository**: it names OpenMRS's URLs, the FHIR audience, database credentials and a
provider from another repository, so it belongs to the deployment. It is kept as an environment-rendered
template in the SMART on FHIR distribution, with a script that imports it into a throwaway Keycloak and
checks through the admin API that everything landed.

## Configuration

Configuration is per authenticator, in the realm: `smart-allowed-audiences`,
`smart-launch-access-url`, `smart-launch-access-secret-key`, `smart-patient-selection-url`,
`smart-launch-secret-key`, `smart-launch-supported-params`.

```json
"authenticatorConfig": [
  {
    "alias": "smart-audience-config",
    "config": { "smart-allowed-audiences": "https://openmrs.example.org/openmrs/ws/fhir2/R4" }
  },
  {
    "alias": "smart-access-config",
    "config": {
      "smart-launch-access-url": "https://openmrs.example.org/openmrs/smartonfhir/smartAccessConfirmation?token={TOKEN}&launch={launchUuid}",
      "smart-launch-access-secret-key": "<base64 secret, shared with the module>"
    }
  },
  {
    "alias": "smart-launch-config",
    "config": {
      "smart-patient-selection-url": "https://openmrs.example.org/openmrs/ms/smartPatientSelection?token={TOKEN}",
      "smart-launch-secret-key": "<the same secret>",
      "smart-launch-supported-params": "patient encounter"
    }
  }
]
```

An execution refers to a block by its alias.

| Key | |
|---|---|
| `smart-allowed-audiences` | FHIR bases an app may name in `aud`. Several, separated by whitespace or commas; matched exactly after trimming one trailing slash, so `https://ehr/fhir` will not accept `https://ehr/fhirEvil`. |
| `smart-launch-access-url` | Where an EHR launch sends the browser so OpenMRS can identify the clinician already signed in there. `{TOKEN}` and `{launchUuid}` are substituted. |
| `smart-launch-access-secret-key` | Signs the token sent to OpenMRS and verifies the one it returns. Both directions, one key. |
| `smart-patient-selection-url` | Where a standalone launch sends the clinician to choose a patient. `{TOKEN}` is substituted. |
| `smart-launch-secret-key` | Signs the token that carries that choice back. The same shared secret. |
| `smart-launch-supported-params` | Which `launch/*` context types this deployment can establish, space separated. A launch asking for anything else is passed over rather than half-served. |

Both secret keys hold the same value the OpenMRS module reads from its own configuration. Treat it as a
private key — anything able to sign with it can assert any username to Keycloak without a password.
Everything here fails closed, so a missing key or audience rejects every request rather than letting one
through unchecked. Neither key has a default, deliberately: a default is a secret every deployment
shares, and an authenticator with nothing configured refuses the launch instead.

## Tests

```bash
mvn test
```

`ProviderContractTest` covers what the compiler cannot: that every authenticator is registered for
Keycloak to discover, that provider ids fit the 36-character column Keycloak stores them in, and that the
audience validator cannot be configured as `ALTERNATIVE` — an audience check a sibling execution can
satisfy instead is not a check. The rest cover the validator's accept and reject matrix, both fail-closed
secret paths, the context mapper, and launch scope extraction.

## The three repositories

| | |
|---|---|
| [openmrs-module-smartonfhir](https://github.com/openmrs/openmrs-module-smartonfhir) | The OpenMRS module. Required. |
| this repository | SMART's OAuth2 extensions for Keycloak. Required. |
| [openmrs-contrib-keycloak-auth](https://github.com/openmrs/openmrs-contrib-keycloak-auth) | OpenMRS as Keycloak's user store, so clinicians use the password they already have. Optional. |

This plugin and the user federation plugin share no code in either direction. The only link is that the
module maps a token to a user by `preferred_username`, so whatever identity source a deployment uses,
that claim must match a real OpenMRS username.

## License

[MPL 2.0 with Healthcare Disclaimer](LICENSE). Add the header to new files with
`mvn com.mycila:license-maven-plugin:format`.
