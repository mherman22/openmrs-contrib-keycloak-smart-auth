Upgrading Keycloak under this plugin
====================================

Every SPI this plugin implements is one Keycloak marks internal — the server logs
`KC-SERVICES0047` for each of our four authenticators and the protocol mapper on every
start. Internal means Keycloak owes us no compatibility, and most of the ways it can break
us produce **no compiler error and no startup error**: an authenticator Keycloak never
invokes, a config key it stores and ignores, a flow that imports and silently skips a
check. This document lists the couplings, worst first, and how to verify each one.

Order of work on a version bump
-------------------------------

1. Bump `keycloak.version` in the root `pom.xml`. Nothing else pins a version.
2. `mvn clean test`. This is the compile-time half: it catches SPI signature changes and
   the constraints in `ProviderContractTest`.
3. `tools/mutation-check.py`. Confirms the security tests still detect the defects they
   were written for, rather than having quietly stopped covering moved code.
4. Deploy and build: copy the JAR into `$KEYCLOAK_HOME/providers/`, run `kc.sh build`,
   start the server. Check the log lists all five providers.
5. Run the distribution's `realm/verify-realm-import.sh` (in
   openmrs-distro-smartonfhir). Realm-side checks live there, not here.
6. Walk both launch types in a **browser**, not with curl: an EHR launch and a standalone
   launch, through to a FHIR call with the issued token. Steps 2–5 have all passed on
   changes that were completely broken in a browser.

The couplings
-------------

### 1. `AlternativeUsernamePasswordFormFactory` subclasses a built-in authenticator

`org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory` is
extended solely to widen `getRequirementChoices()`. Keycloak's built-in offers only
`REQUIRED` in 26.7.1, which cannot sit in an alternative sub-flow beside the SMART
authenticators.

It declares its own id, `smart-username-password-form`, and does **not** inherit
`auth-username-password-form`. Inheriting it registered our subclass under the built-in's
id, which replaced the stock login form for every realm in the instance — and invisibly,
because the display name was inherited too.

*Verify:* `mvn test`. `ProviderContractTest.getRequirementChoices_shouldStillNeedTheAlternativeLoginForm`
fails if the new Keycloak's built-in has gained `ALTERNATIVE` — in which case delete this
class, its services entry and the realm's reference to it, and use the built-in.
`getId_shouldNotShadowKeycloaksBuiltInLoginForm` fails if the ids or display names collide
again. Both compile against the new version, so a renamed or relocated superclass shows up
as a compile error rather than silence.

### 2. Provider ids used as authenticators must be at most 36 characters

Keycloak stores an execution's authenticator id in `AUTHENTICATION_EXECUTION.AUTHENTICATOR`,
a `VARCHAR(36)`. A longer id compiles, registers and appears in the admin console, then
fails realm import with *"Value too long for column"*. It is not a code-level constraint, so
nothing else warns.

*Verify:* `mvn test` — `ProviderContractTest.getId_shouldFitProviderIdsInTheColumnKeycloakStoresThemIn`
asserts it for every registered factory. The test pins 36 as a constant, so if a Keycloak
release widens or narrows the column, confirm the width against the upgraded server rather
than the test:

```bash
# from the distribution jar's schema changelog
unzip -p $KEYCLOAK_HOME/lib/lib/main/org.keycloak.keycloak-model-jpa-*.jar 'META-INF/jpa-changelog-*.xml' \
  | grep -B2 -A6 'AUTHENTICATION_EXECUTION' | grep -i -A3 'name="AUTHENTICATOR"'

# or, against a database Keycloak has already migrated
SELECT character_maximum_length FROM information_schema.columns
 WHERE table_name = 'AUTHENTICATION_EXECUTION' AND column_name = 'AUTHENTICATOR';
```

### 3. Keycloak ignores `ALTERNATIVE` siblings once anything at the same level is `REQUIRED`

Within one flow level, a `REQUIRED` execution makes Keycloak skip the `ALTERNATIVE`
executions beside it. The wiring this plugin is designed for therefore puts the audience
validator as a `REQUIRED` first step and the alternatives — EHR launch, standalone launch,
login form — inside a `REQUIRED` sub-flow of their own. Flatten that, or add a second
`REQUIRED` execution at the top level, and the alternatives stop running: the launch appears
to succeed and no launch context is ever established.

The plugin side of this is that the audience validator refuses to offer `ALTERNATIVE` at all
(`SmartAudienceValidatorFactory.REQUIREMENT_CHOICES`). An audience check a sibling execution
can satisfy on its behalf is not a check.

*Verify:* `mvn test` covers the refusal
(`ProviderContractTest.getRequirementChoices_shouldRefuseToRunTheAudienceValidatorAsAlternative`).
The composition itself lives in the realm, so it is verified by the distribution's
`verify-realm-import.sh` and, ultimately, by a browser launch: a flow that skips the
alternatives still returns a token, so only an end-to-end launch distinguishes it.

### 4. Config key spellings that import cleanly and silently do nothing

Keycloak accepts any key in a mapper or authenticator config map and ignores what it does
not recognise. Two spellings have already cost a debugging session each:

| Correct | Wrong but accepted |
|---|---|
| `access.tokenResponse.claim` | `access.token.response.claim` |
| `included.custom.audience` | anything else on `oidc-audience-mapper` |

**Never guess or copy these from documentation.** Read them from the running server:

```bash
# every property name the SMART context mapper actually reads
curl -s -H "Authorization: bearer $TOKEN" "$KC/admin/serverinfo" \
  | jq -r '.protocolMapperTypes["openid-connect"][]
           | select(.id == "smart-context-claim-mapper") | .properties[].name'

# same for the built-in audience mapper
curl -s -H "Authorization: bearer $TOKEN" "$KC/admin/serverinfo" \
  | jq -r '.protocolMapperTypes["openid-connect"][]
           | select(.id == "oidc-audience-mapper") | .properties[].name'

# our own authenticator config keys, with their defaults
curl -s -H "Authorization: bearer $TOKEN" \
  "$KC/admin/realms/$REALM/authentication/config-description/smart-audience-validator" | jq
```

The audience mapper also has to be attached to a **client scope that is a realm default**,
never to a single client. On one client it produces a realm where exactly one app can reach
FHIR and every other one 401s after an apparently perfect launch. Both of these are realm
concerns and are checked in the distribution; they are listed here because an upgrade that
changes a key name breaks them silently on this side.

### 5. Action tokens

`SmartPatientSelectionActionTokenHandler` and `SmartLaunchAccessActionTokenHandler` extend
`AbstractActionTokenHandler`, their tokens extend `DefaultActionToken`, and the return URL is
built with `Urls.actionTokenBuilder(...)` plus `Constants.EXECUTION`. `handleToken` calls
`tokenContext.processFlow(...)` with a five-argument signature that has changed before.

Note that the EHR-launch path deliberately does **not** use an action token: an EHR launch has
nobody authenticated yet, and the action-token endpoint requires the token to name a user.
Naming the literal username `admin` to satisfy it fails on a stock OpenMRS database, where the
administrator's `username` column is NULL and `admin` is its `system_id`.

*Verify:* signature changes are compile errors, so `mvn test` is the first gate. Behaviour needs
a browser walk of a standalone launch (step 6): the token round-trips through OpenMRS, so a
changed URL shape or a rejected token only shows up there.

### 6. Unrecognised authorization-endpoint parameters arrive as prefixed client notes

`SmartAudienceValidator` reads `aud` from the client note `client_request_param_aud`
(`CLIENT_REQUEST_PARAM_PREFIX`), because that is where Keycloak copies query parameters it does
not recognise. If Keycloak stops doing this, or starts recognising `aud` itself, the note is
absent — and the validator then rejects every request, which is the safe direction but a total
outage.

*Verify:* a browser launch. `mvn test` cannot see this: the tests set the note themselves. If
launches start failing with *"SMART App Launch requires an 'aud' parameter"* while the app is
sending one, this is the coupling that moved.

### 7. HMAC signing and verification internals

`KeyWrapper`, `MacSignatureSignerContext`, `JWSBuilder`, `TokenVerifier`, `JavaAlgorithm.HS256`
and `Base64` from `keycloak-core` sign the token sent to OpenMRS and verify the one it returns.
The OpenMRS module verifies with the same shared secret, so a change in how Keycloak builds the
JWS breaks the pair, not just this side.

*Verify:* `mvn test` compiles against them and `SmartLaunchSecretTest` exercises key
construction. Round-tripping needs the module: step 6.

### 8. Token-response mapping

`SmartContextClaimMapper` extends `AbstractOIDCProtocolMapper`, implements
`OIDCAccessTokenResponseMapper`, and calls `OIDCAttributeMapperHelper.mapClaim(...)`
(`splitClaimPath` was removed in favour of it). SMART 2.x puts launch context in the token
response, not only in the access token, so losing `OIDCAccessTokenResponseMapper` means apps
receive a token with no `patient` or `encounter` and no error.

*Verify:* `mvn test` (`SmartContextClaimMapperTest`), then inspect a real token response in step 6.

### 9. Packaging and Java version

A plain JAR in `providers/`, activated by `kc.sh build` — Quarkus, not WildFly. There is no EAR
and no `module.xml`; do not reintroduce them. The build targets Java 17 bytecode
(`maven.compiler.release=17`) and Keycloak 26 runs on 21, so CI builds both
(`.github/workflows/main.yml`, `java_versions: '[17, 21]'`). A Keycloak release that raises its
baseline means raising `maven.compiler.release` and that matrix together.

What the tests can and cannot tell you
--------------------------------------

`mvn test` plus `tools/mutation-check.py` cover provider identity, the audience match, the
fail-closed paths and the launch-context claims — see the coverage table in the README. They
cover **nothing** about the realm: flow composition, client scopes, the audience mapper's
placement, PKCE, and every config key spelling are realm-side and belong to the distribution's
`verify-realm-import.sh`. And no test in either repository establishes that a launch works;
only a browser does.
