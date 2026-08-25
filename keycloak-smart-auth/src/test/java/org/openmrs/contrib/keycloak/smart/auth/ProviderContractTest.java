/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.openmrs.contrib.keycloak.smart.auth.provider.AlternativeUsernamePasswordFormFactory;

/**
 * Constraints on provider identity that Keycloak enforces at realm-import time rather than at compile
 * time. Each assertion here corresponds to a failure that has actually happened during this port.
 */
public class ProviderContractTest {

	/**
	 * AUTHENTICATION_EXECUTION.AUTHENTICATOR is a VARCHAR(36); a longer id compiles and registers, then
	 * fails realm import.
	 */
	private static final int MAX_AUTHENTICATOR_ID_LENGTH = 36;

	private static final String SERVICES_FILE = "META-INF/services/" + AuthenticatorFactory.class.getName();

	static List<AuthenticatorFactory> factories() throws Exception {
		List<AuthenticatorFactory> factories = new ArrayList<>();
		for (String className : declaredFactoryClassNames()) {
			factories.add((AuthenticatorFactory) Class.forName(className).getDeclaredConstructor().newInstance());
		}
		return factories;
	}

	/** Reads the service registration file, so the test covers what Keycloak will actually load. */
	private static List<String> declaredFactoryClassNames() throws IOException {
		try (InputStream in = ProviderContractTest.class.getClassLoader().getResourceAsStream(SERVICES_FILE)) {
			if (in == null) {
				throw new IOException("missing service registration file: " + SERVICES_FILE);
			}
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
				return reader.lines().map(String::trim).filter(l -> !l.isEmpty() && !l.startsWith("#"))
						.collect(Collectors.toList());
			}
		}
	}

	@Test
	public void factories_shouldRegisterEveryAuthenticatorForDiscovery() throws Exception {
		List<String> declared = declaredFactoryClassNames();

		// A factory with no services entry fails silently: it never appears in Keycloak.
		assertTrue(declared.contains(AlternativeUsernamePasswordFormFactory.class.getName()));
		assertTrue(declared.stream().anyMatch(n -> n.endsWith("SmartAudienceValidatorFactory")),
				"the audience validator must be registered or SMART's aud requirement goes unenforced");
		assertTrue(declared.stream().anyMatch(n -> n.endsWith("SmartLaunchAuthenticatorFactory")));
		assertTrue(declared.stream().anyMatch(n -> n.endsWith("SmartLaunchAccessAuthenticatorFactory")));
		assertEquals(4, declared.size(), "unexpected number of registered authenticators; update this test deliberately");
	}

	@MethodSource("factories")
	@ParameterizedTest(name = "{0}")
	public void getId_shouldFitProviderIdsInTheColumnKeycloakStoresThemIn(AuthenticatorFactory factory) {
		String id = factory.getId();

		assertTrue(id.length() <= MAX_AUTHENTICATOR_ID_LENGTH,
				String.format("provider id '%s' is %d characters; Keycloak's AUTHENTICATOR column holds %d",
						id, id.length(), MAX_AUTHENTICATOR_ID_LENGTH));
	}

	@MethodSource("factories")
	@ParameterizedTest(name = "{0}")
	public void getId_shouldUseProviderIdsThatNeedNoUrlEscaping(AuthenticatorFactory factory) {
		String id = factory.getId();

		assertFalse(id.trim().isEmpty(), "a blank provider id cannot be referenced from a flow");
		assertTrue(id.matches("[a-z0-9-]+"),
				"provider id '" + id + "' should be lowercase kebab-case; it appears in realm JSON and admin URLs");
	}

	@Test
	public void getId_shouldGiveEveryProviderAUniqueId() throws Exception {
		List<String> ids = factories().stream().map(AuthenticatorFactory::getId).collect(Collectors.toList());
		Set<String> unique = new HashSet<>(ids);

		assertEquals(ids.size(), unique.size(), "duplicate provider ids: one silently shadows the other. " + ids);
	}

	/**
	 * Inheriting getId() registered this as auth-username-password-form, replacing the stock login form
	 * for every realm in the instance, and invisibly, since the display name was inherited too.
	 */
	@Test
	public void getId_shouldNotShadowKeycloaksBuiltInLoginForm() {
		AlternativeUsernamePasswordFormFactory ours = new AlternativeUsernamePasswordFormFactory();
		UsernamePasswordFormFactory builtIn = new UsernamePasswordFormFactory();

		assertNotEquals(builtIn.getId(), ours.getId(),
				"sharing the built-in id replaces the stock login form instance-wide");
		assertNotEquals(builtIn.getDisplayType(), ours.getDisplayType(),
				"an identical display name makes the two indistinguishable in the admin console");
	}

	/**
	 * The subclass exists only to widen the requirement choices. If a future Keycloak offers
	 * ALTERNATIVE on the built-in, this fails and the subclass can be deleted.
	 */
	@Test
	public void getRequirementChoices_shouldStillNeedTheAlternativeLoginForm() {
		Set<AuthenticationExecutionModel.Requirement> builtIn = new HashSet<>(
				Arrays.asList(new UsernamePasswordFormFactory().getRequirementChoices()));
		Set<AuthenticationExecutionModel.Requirement> ours = new HashSet<>(
				Arrays.asList(new AlternativeUsernamePasswordFormFactory().getRequirementChoices()));

		assertFalse(builtIn.contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE),
				"Keycloak's built-in form now offers ALTERNATIVE; AlternativeUsernamePasswordFormFactory is redundant "
						+ "and should be removed along with its realm reference");
		assertTrue(ours.contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE));
	}

	/**
	 * An audience check that another alternative execution can satisfy on its behalf is not a check.
	 */
	@Test
	public void getRequirementChoices_shouldRefuseToRunTheAudienceValidatorAsAlternative() throws Exception {
		AuthenticatorFactory validator = factories().stream()
				.filter(f -> f.getId().equals("smart-audience-validator")).findFirst()
				.orElseThrow(() -> new AssertionError("audience validator not registered"));

		Set<AuthenticationExecutionModel.Requirement> choices = new HashSet<>(
				Arrays.asList(validator.getRequirementChoices()));

		assertFalse(choices.contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE),
				"ALTERNATIVE would let a sibling execution satisfy the flow without validating aud");
		assertTrue(choices.contains(AuthenticationExecutionModel.Requirement.REQUIRED));
	}

	@MethodSource("factories")
	@ParameterizedTest(name = "{0}")
	public void getConfigProperties_shouldDescribeConfigurationWithoutFailing(AuthenticatorFactory factory) {
		assertDoesNotThrow(factory::getConfigProperties,
				"the admin console calls this to render the configuration form");
		assertDoesNotThrow(factory::getDisplayType);
		assertDoesNotThrow(factory::getHelpText);

		if (factory.isConfigurable()) {
			assertFalse(factory.getConfigProperties().isEmpty(),
					factory.getId() + " claims to be configurable but exposes no properties");
		}
	}
}
