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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The launch types derived here are handed to OpenMRS as the {@code launchType} claim and decide which
 * picker the user is shown. The value used to carry a leading slash, because the prefix is seven
 * characters and the code cut six; OpenMRS matched it with {@code contains}, so the defect was
 * invisible from either end.
 */
public class SmartLaunchAuthenticatorScopeTest {

	private SmartLaunchAuthenticator authenticator;

	@BeforeEach
	public void setUp() {
		authenticator = new SmartLaunchAuthenticator();
	}

	@CsvSource(nullValues = "NULL", value = {
			"'openid launch/patient',                      patient",
			"'launch/patient',                             patient",
			"'launch/encounter',                           encounter",
			"'openid launch/patient launch/encounter',     'patient encounter'",
			"'launch/encounter launch/patient',            'encounter patient'",
			// no launch scopes at all
			"'openid profile fhirUser',                    ''",
			"'',                                           ''",
			"NULL,                                         ''",
			// bare launch is the EHR-launch scope and names no context type
			"'launch',                                      ''",
			"'openid launch',                               ''",
			// v2 permission scopes are not launch scopes
			"'patient/Observation.rs launch/patient',      patient",
			// irregular whitespace
			"'  launch/patient   launch/encounter  ',      'patient encounter'",
			"'openid\tlaunch/patient',                     patient",
	})
	@ParameterizedTest(name = "scope [{0}] yields launch types [{1}]")
	public void getLaunchScopes_shouldExtractLaunchTypesWithoutThePrefix(String scope, String expected) {
		assertEquals(expected == null ? "" : expected, authenticator.getLaunchScopes(scope));
	}

	/**
	 * The regression itself. Any leading slash means the prefix was cut at the wrong offset.
	 */
	@ValueSource(strings = { "launch/patient", "openid launch/patient launch/encounter", "launch/encounter" })
	@ParameterizedTest(name = "no launch type from [{0}] retains a slash")
	public void getLaunchScopes_shouldNeverRetainThePrefixSlashInALaunchType(String scope) {
		String result = authenticator.getLaunchScopes(scope);

		assertFalse(result.contains("/"),
				"launch types should be bare context names, but got: " + result);
		for (String type : result.split("\\s+")) {
			assertFalse(type.startsWith("/"), "launch type retained a leading slash: " + type);
		}
	}

	/**
	 * A scope that merely contains the prefix is not a launch scope. This is what separates a
	 * startsWith check from a contains check.
	 */
	@ValueSource(strings = { "xlaunch/patient", "prelaunch/patient", "a-launch/patient", "notlaunch/encounter" })
	@ParameterizedTest(name = "[{0}] is not a launch scope")
	public void getLaunchScopes_shouldIgnoreScopesThatMerelyContainThePrefix(String scope) {
		assertEquals("", authenticator.getLaunchScopes(scope));
	}

	@Test
	public void getLaunchScopes_shouldExtractExactlyWhatTheOpenmrsPickersSwitchOn() {
		// SmartLaunchOptionSelected on the OpenMRS side tests for these two tokens.
		Set<String> produced = new HashSet<>(
				Arrays.asList(authenticator.getLaunchScopes("launch/patient launch/encounter").split("\\s+")));

		assertEquals(new HashSet<>(Arrays.asList("patient", "encounter")), produced);
	}

	@Test
	public void launchScopePrefix_shouldKeepThePrefixTheOffsetsDependOn() {
		assertEquals("launch/", SmartLaunchAuthenticator.LAUNCH_SCOPE_PREFIX);
		assertEquals(7, SmartLaunchAuthenticator.LAUNCH_SCOPE_PREFIX.length());
	}

	@Test
	public void getLaunchScopes_shouldNotCollapseDuplicateLaunchScopesIntoAMalformedValue() {
		String result = authenticator.getLaunchScopes("launch/patient launch/patient");

		List<String> types = Arrays.asList(result.split("\\s+"));
		types.forEach(t -> assertEquals("patient", t));
	}
}
