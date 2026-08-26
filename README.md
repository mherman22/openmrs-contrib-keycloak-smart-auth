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
[UPGRADING.md](UPGRADING.md) lists those couplings and how to verify each one on a version bump.

## The JAR alone does nothing

Nothing here registers itself into an authentication flow, so a provider Keycloak has loaded but never
invokes is invisible. The wiring — flow, client, scopes, mappers — lives in a realm, and the realm is
**not in this repository**: it names OpenMRS's URLs, the FHIR audience, database credentials and a
provider from another repository, so it belongs to the deployment. It is kept as an environment-rendered
template in the SMART on FHIR distribution, with a script that imports it into a throwaway Keycloak and
checks through the admin API that everything landed.

## Configuration

Configuration is per authenticator, in the realm: `smart_allowed_audiences`,
`smart_launch_access_url`, `smart_launch_access_secret_key`, `smart_patient_selection_url`,
`smart_launch_secret_key`, `smart_launch_supported_params`.

```json
"authenticatorConfig": [
  {
    "alias": "smart-audience-config",
    "config": { "smart_allowed_audiences": "https://openmrs.example.org/openmrs/ws/fhir2/R4" }
  },
  {
    "alias": "smart-access-config",
    "config": {
      "smart_launch_access_url": "https://openmrs.example.org/openmrs/smartonfhir/smartAccessConfirmation?token={TOKEN}&launch={launchUuid}",
      "smart_launch_access_secret_key": "<base64 secret, shared with the module>"
    }
  },
  {
    "alias": "smart-launch-config",
    "config": {
      "smart_patient_selection_url": "https://openmrs.example.org/openmrs/ms/smartPatientSelection?token={TOKEN}",
      "smart_launch_secret_key": "<the same secret>",
      "smart_launch_supported_params": "patient encounter"
    }
  }
]
```

An execution refers to a block by its alias.

| Key | |
|---|---|
| `smart_allowed_audiences` | FHIR bases an app may name in `aud`. Several, separated by whitespace or commas; matched exactly after trimming one trailing slash, so `https://ehr/fhir` will not accept `https://ehr/fhirEvil`. |
| `smart_launch_access_url` | Where an EHR launch sends the browser so OpenMRS can identify the clinician already signed in there. `{TOKEN}` and `{launchUuid}` are substituted. |
| `smart_launch_access_secret_key` | Verifies the signed token OpenMRS returns naming the clinician. The EHR path signs nothing itself: it hands the browser a return URL, not a token. |
| `smart_patient_selection_url` | Where a standalone launch sends the clinician to choose a patient. `{TOKEN}` is substituted. |
| `smart_launch_secret_key` | Signs the token that carries that choice back. The same shared secret. |
| `smart_launch_supported_params` | Which `launch/*` context types this deployment can establish, space separated. A launch asking for anything else is passed over rather than half-served. |

Both secret keys hold the same value the OpenMRS module reads from its own configuration. Treat it as a
private key — anything able to sign with it can assert any username to Keycloak without a password.
Everything here fails closed, so a missing key or audience rejects every request rather than letting one
through unchecked. Neither key has a default, deliberately: a default is a secret every deployment
shares, and an authenticator with nothing configured refuses the launch instead.
