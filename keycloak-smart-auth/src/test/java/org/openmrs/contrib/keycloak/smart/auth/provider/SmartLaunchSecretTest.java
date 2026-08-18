/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * The shared secret authenticates the app token that establishes launch context and, on an EHR launch,
 * the clinician's identity: {@code SmartLaunchAccessAuthenticator.action} takes the token's subject as
 * the signed-in user and no password is presented anywhere in that flow. Anything able to sign with the
 * key can therefore assert any username, so an unconfigured deployment must reject the launch rather
 * than fall back to a key an attacker also knows.
 * <p>
 * These are the tests for that, in both directions: the authenticators refuse a blank key, and the
 * factories offer no default that would make one look configured.
 */
public class SmartLaunchSecretTest {

	/** "smart-launch-secret" base64-encoded; any valid base64 does, the bytes are never interpreted. */
	private static final String SECRET = "c21hcnQtbGF1bmNoLXNlY3JldA==";

	private static AuthenticatorConfigModel config(String key, String value) {
		AuthenticatorConfigModel config = new AuthenticatorConfigModel();
		Map<String, String> values = new HashMap<>();
		if (value != null) {
			values.put(key, value);
		}
		config.setConfig(values);
		return config;
	}

	private static ProviderConfigProperty property(List<ProviderConfigProperty> properties, String name) {
		Optional<ProviderConfigProperty> found = properties.stream().filter(p -> name.equals(p.getName())).findFirst();
		return found.orElseThrow(() -> new AssertionError("no config property named " + name));
	}

	@Nested
	public class StandaloneLaunch {

		private final SmartLaunchAuthenticator authenticator = new SmartLaunchAuthenticator();

		private final String key = SmartLaunchAuthenticatorFactory.CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY;

		@Test
		public void getSecretKey_shouldFailClosedWithNoAuthenticatorConfig() {
			assertThrows(AuthenticationFlowException.class, () -> authenticator.getSecretKey(null, "openmrs"));
		}

		@Test
		public void getSecretKey_shouldFailClosedWhenTheSecretKeyIsAbsent() {
			AuthenticatorConfigModel config = config(key, null);

			assertThrows(AuthenticationFlowException.class, () -> authenticator.getSecretKey(config, "openmrs"));
		}

		@ValueSource(strings = { "", " ", "   ", "\t", "\n" })
		@ParameterizedTest(name = "blank secret [{0}]")
		public void getSecretKey_shouldFailClosedOnABlankSecret(String secret) {
			AuthenticatorConfigModel config = config(key, secret);

			assertThrows(AuthenticationFlowException.class, () -> authenticator.getSecretKey(config, "openmrs"));
		}

		@Test
		public void getSecretKey_shouldReturnAnHmacKeyWhenConfigured() throws Exception {
			SecretKeySpec secretKey = authenticator.getSecretKey(config(key, SECRET), "openmrs");

			assertEquals(JavaAlgorithm.HS256, secretKey.getAlgorithm());
			assertArrayEquals("smart-launch-secret".getBytes("UTF-8"), secretKey.getEncoded());
		}
	}

	@Nested
	public class EhrLaunch {

		private final SmartLaunchAccessAuthenticator authenticator = new SmartLaunchAccessAuthenticator();

		private final String key = SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY;

		@Test
		public void getSecretKey_shouldFailClosedWithNoAuthenticatorConfig() {
			assertThrows(AuthenticationFlowException.class, () -> authenticator.getSecretKey(null, "openmrs"));
		}

		@Test
		public void getSecretKey_shouldFailClosedWhenTheSecretKeyIsAbsent() {
			AuthenticatorConfigModel config = config(key, null);

			assertThrows(AuthenticationFlowException.class, () -> authenticator.getSecretKey(config, "openmrs"));
		}

		@ValueSource(strings = { "", " ", "   ", "\t", "\n" })
		@ParameterizedTest(name = "blank secret [{0}]")
		public void getSecretKey_shouldFailClosedOnABlankSecret(String secret) {
			AuthenticatorConfigModel config = config(key, secret);

			assertThrows(AuthenticationFlowException.class, () -> authenticator.getSecretKey(config, "openmrs"));
		}

		@Test
		public void getSecretKey_shouldReturnAnHmacKeyWhenConfigured() throws Exception {
			SecretKeySpec secretKey = authenticator.getSecretKey(config(key, SECRET), "openmrs");

			assertEquals(JavaAlgorithm.HS256, secretKey.getAlgorithm());
			assertArrayEquals("smart-launch-secret".getBytes("UTF-8"), secretKey.getEncoded());
		}
	}

	/**
	 * A default of {@code ""} is what this used to ship. It reads as a configured value in the admin
	 * console and in a realm export, while being a key every deployment shares, so the launch context
	 * and the username the app token asserts could be forged by anyone who read the source.
	 */
	@Nested
	public class Defaults {

		@Test
		public void getConfigProperties_shouldOfferNoDefaultForTheStandaloneLaunchSecret() {
			ProviderConfigProperty secret = property(new SmartLaunchAuthenticatorFactory().getConfigProperties(),
					SmartLaunchAuthenticatorFactory.CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY);

			assertNull(secret.getDefaultValue(), "a defaulted launch secret is a shared secret nobody chose");
			assertEquals(ProviderConfigProperty.PASSWORD, secret.getType(), "the secret must be masked in the console");
		}

		@Test
		public void getConfigProperties_shouldOfferNoDefaultForTheEhrLaunchSecret() {
			ProviderConfigProperty secret = property(new SmartLaunchAccessAuthenticatorFactory().getConfigProperties(),
					SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY);

			assertNull(secret.getDefaultValue(), "a defaulted launch secret is a shared secret nobody chose");
			assertEquals(ProviderConfigProperty.PASSWORD, secret.getType(), "the secret must be masked in the console");
		}

		/**
		 * The audience validator is the precedent this follows; if it ever grows a default, the
		 * reasoning above stopped being applied consistently.
		 */
		@Test
		public void getConfigProperties_shouldOfferNoDefaultForTheAllowedAudiences() {
			ProviderConfigProperty audiences = property(new SmartAudienceValidatorFactory().getConfigProperties(),
					SmartAudienceValidatorFactory.CONFIG_ALLOWED_AUDIENCES);

			assertNull(audiences.getDefaultValue());
		}
	}
}
