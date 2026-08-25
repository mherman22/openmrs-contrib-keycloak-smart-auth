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
 * Widens the built-in username/password form's REQUIRED-only choices so it can join an alternative
 * sub-flow. Its own provider id, since sharing the built-in one would replace the stock form.
 */
public class AlternativeUsernamePasswordFormFactory extends UsernamePasswordFormFactory {

	// At most 36 characters: AUTHENTICATION_EXECUTION.AUTHENTICATOR is VARCHAR(36).
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
