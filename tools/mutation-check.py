#!/usr/bin/env python3
"""Reintroduce each real defect and assert the corresponding test fails.

A test that keeps passing while the defect is present is not testing anything, so
this is the check that the security tests are real rather than decorative. Every
mutation below is either a defect that actually occurred while porting to Keycloak
26, or the weakening a plausible "make it work again" change would introduce.

    tools/mutation-check.py             # every mutation
    tools/mutation-check.py audience    # only mutations whose label matches

Needs JDK 17 or 21 (Keycloak 26 will not compile on 8), so set JAVA_HOME if the
default on the PATH is older:

    JAVA_HOME=/path/to/jdk-17 tools/mutation-check.py

Not run in CI: it edits files in the working tree and runs the suite once per
mutation, which is minutes of build for a property CI cannot usefully re-check on
every push. It is the reviewer's and the upgrader's tool -- see UPGRADING.md.

Exits non-zero if any defect goes undetected, or if a mutation pattern has gone
stale because the code moved: a stale pattern means that defect is no longer being
checked for, which is indistinguishable from having no test at all.
"""
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.path.join(REPO, "keycloak-smart-auth")
SRC = os.path.join(MODULE, "src/main/java/org/openmrs/contrib/keycloak/smart/auth")
SERVICES = os.path.join(MODULE, "src/main/resources/META-INF/services",
                        "org.keycloak.authentication.AuthenticatorFactory")

# The source-shaping plugins are bound to the build and would rewrite the mutated file
# out from under the test run.
MVN = ["mvn", "-B", "-ntp", "-Dlicense.skip=true", "-Dformatter.skip=true",
       "-Dimpsort.skip=true", "-Djacoco.skip=true"]


def src(*path):
    return os.path.join(SRC, *path)


# (label, test class, file, find, replace)
MUTATIONS = [
    # --- provider identity: what Keycloak enforces at realm-import time, not at compile time
    ("provider id over Keycloak's 36-character column",
     "ProviderContractTest", src("provider/SmartAudienceValidatorFactory.java"),
     '"smart-audience-validator"', '"smart-audience-validator-for-fhir-srv"'),

    ("audience validator left unregistered, so Keycloak never loads it",
     "ProviderContractTest", SERVICES,
     "org.openmrs.contrib.keycloak.smart.auth.provider.SmartAudienceValidatorFactory\n", ""),

    ("login form re-registered under the built-in id, overriding the stock form instance-wide",
     "ProviderContractTest", src("provider/AlternativeUsernamePasswordFormFactory.java"),
     '"smart-username-password-form"', '"auth-username-password-form"'),

    ("audience validator offered as ALTERNATIVE, so a sibling execution can satisfy it",
     "ProviderContractTest", src("provider/SmartAudienceValidatorFactory.java"),
     """			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.DISABLED""",
     """			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.ALTERNATIVE,
			AuthenticationExecutionModel.Requirement.DISABLED"""),

    # --- the audience match itself
    ("audience matched by prefix, so https://ehr/fhirEvil passes",
     "SmartAudienceValidatorTest", src("provider/SmartAudienceValidator.java"),
     "if (!allowed.contains(normalize(presented))) {",
     "if (allowed.stream().noneMatch(a -> normalize(presented).startsWith(a))) {"),

    ("audience matched case-insensitively, accepting a host the operator did not sanction",
     "SmartAudienceValidatorTest", src("provider/SmartAudienceValidator.java"),
     '		String trimmed = audience.trim();\n		return trimmed.endsWith("/")',
     '		String trimmed = audience.trim().toLowerCase();\n		return trimmed.endsWith("/")'),

    ("trailing-slash normalisation dropped, so a configured base stops matching itself",
     "SmartAudienceValidatorTest", src("provider/SmartAudienceValidator.java"),
     'return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;',
     'return trimmed;'),

    # --- failing closed
    ("unconfigured audience validator waves the request through",
     "SmartAudienceValidatorTest", src("provider/SmartAudienceValidator.java"),
     """		if (allowed.isEmpty()) {
			// Fail closed: an unconfigured validator must not wave requests through.
			reject(context, "No allowed FHIR audience is configured for this authenticator");
			return;
		}""",
     """		if (allowed.isEmpty()) {
			context.success();
			return;
		}"""),

    ("standalone launch falls back to a built-in secret when none is configured",
     "SmartLaunchSecretTest", src("provider/SmartLaunchAuthenticator.java"),
     """		if (StringUtils.isBlank(secretKey)) {
			logger.warnf("Refusing to sign or verify a SMART launch token: %s is not configured for realm %s",
					SmartLaunchAuthenticatorFactory.CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY, realmName);
			throw new AuthenticationFlowException("Secret key is not configured for realm " + realmName,
					AuthenticationFlowError.INTERNAL_ERROR);
		}""",
     """		if (StringUtils.isBlank(secretKey)) {
			secretKey = "ZGVmYXVsdA==";
		}"""),

    ("EHR launch falls back to a built-in secret, so anyone can assert any username",
     "SmartLaunchSecretTest", src("provider/SmartLaunchAccessAuthenticator.java"),
     """		if (StringUtils.isBlank(secretKey)) {
			logger.warnf("Refusing to sign or verify a SMART launch token: %s is not configured for realm %s",
					SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY, realmName);
			throw new AuthenticationFlowException("Secret key is not configured for realm " + realmName,
					AuthenticationFlowError.INTERNAL_ERROR);
		}""",
     """		if (StringUtils.isBlank(secretKey)) {
			secretKey = "ZGVmYXVsdA==";
		}"""),

    ("empty default restored on the standalone launch secret",
     "SmartLaunchSecretTest", src("provider/SmartLaunchAuthenticatorFactory.java"),
     "PASSWORD, null);", 'PASSWORD, "");'),

    ("empty default restored on the EHR launch secret",
     "SmartLaunchSecretTest", src("provider/SmartLaunchAccessAuthenticatorFactory.java"),
     "PASSWORD, null);", 'PASSWORD, "");'),

    # --- launch context, which the app receives and acts on
    ("encounter context reported as 'visit', leaking OpenMRS jargon to the app",
     "SmartContextClaimMapperTest", src("mapper/SmartContextClaimMapper.java"),
     'put("encounter", visitUuid)', 'put("visit", visitUuid)'),

    ("mapper stops writing to the token response, where SMART context belongs",
     "SmartContextClaimMapperTest", src("mapper/SmartContextClaimMapper.java"),
     "OIDCAttributeMapperHelper.mapClaim(token, mappingModel, attributeValue);", ""),

    ("launch scope cut one character short, so the launch type keeps a leading slash",
     "SmartLaunchAuthenticatorScopeTest", src("provider/SmartLaunchAuthenticator.java"),
     "it.substring(LAUNCH_SCOPE_PREFIX.length())", "it.substring(LAUNCH_SCOPE_PREFIX.length() - 1)"),
]


def mvn(*args):
    proc = subprocess.run(MVN + list(args), cwd=REPO, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    selected = [m for m in MUTATIONS if not sys.argv[1:] or any(a in m[0] for a in sys.argv[1:])]
    if not selected:
        print("no mutation label matches %s" % " ".join(sys.argv[1:]))
        return 2

    print("Checking the suite passes before mutating anything.")
    rc, out = mvn("test")
    if rc != 0:
        print(out[-3000:])
        print("\nBaseline suite does not pass, so no mutation result would mean anything.")
        print("If this is a compiler error, check JAVA_HOME: Keycloak 26 needs JDK 17 or later.")
        return 2

    detected, missed, stale = 0, [], []
    print("\nReintroducing each defect to confirm the tests detect it.\n")

    for label, test_class, path, find, replace in selected:
        original = open(path).read()
        if find not in original:
            print("--- %s\n    STALE    pattern not found in %s; this defect is no longer covered"
                  % (label, os.path.relpath(path, REPO)))
            stale.append(label)
            continue

        backup = os.path.join(tempfile.mkdtemp(), os.path.basename(path))
        shutil.copy(path, backup)
        try:
            with open(path, "w") as f:
                f.write(original.replace(find, replace, 1))
            rc, out = mvn("test", "-Dtest=" + test_class)
            print("--- %s" % label)
            if rc == 0:
                print("    MISSED   %s still passes with the defect present" % test_class)
                missed.append(label)
            else:
                failures = [l.strip() for l in out.splitlines()
                            if l.startswith("[ERROR]   " + test_class)]
                print("    CAUGHT   %s" % (failures[0][10:] if failures else test_class))
                detected += 1
        finally:
            shutil.copy(backup, path)
            shutil.rmtree(os.path.dirname(backup))

    print("\n=== mutation coverage ===")
    print("  detected: %d / %d" % (detected, len(selected) - len(stale)))
    for label in missed:
        print("  MISSED:   %s" % label)
    for label in stale:
        print("  STALE:    %s" % label)
    return 1 if missed or stale else 0


if __name__ == "__main__":
    sys.exit(main())
