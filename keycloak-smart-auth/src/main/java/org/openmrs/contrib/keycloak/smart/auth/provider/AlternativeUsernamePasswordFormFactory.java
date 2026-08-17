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

import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.AuthenticationExecutionModel;

/**
 * Keycloak's built-in username/password form only offers REQUIRED, which cannot be combined with the
 * SMART authenticators in an alternative sub-flow. This subclass widens the requirement choices and
 * changes nothing else.
 * <p>
 * It deliberately declares its own provider id rather than inheriting
 * {@code auth-username-password-form} from the superclass. Sharing the built-in id would silently
 * replace the stock form for every realm in the instance, since Keycloak keys authenticators by id
 * and {@code DefaultAuthenticationFlows} wires the built-in id into the browser, direct-grant and
 * reset-credentials flows. With a distinct id those flows keep the built-in, and only flows that ask
 * for this authenticator get it.
 */
public class AlternativeUsernamePasswordFormFactory extends UsernamePasswordFormFactory {

	// Must stay within 36 characters: Keycloak stores this in
	// AUTHENTICATION_EXECUTION.AUTHENTICATOR, which is VARCHAR(36), and a longer id
	// fails realm import with "Value too long for column".
	public static final String PROVIDER_ID = "smart-username-password-form";

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.ALTERNATIVE,
			AuthenticationExecutionModel.Requirement.DISABLED
	};

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "Username Password Form (alternative-capable)";
	}

	@Override
	public String getHelpText() {
		return "Validates a username and password as the built-in form does, but may also be configured as ALTERNATIVE or DISABLED.";
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}
}
