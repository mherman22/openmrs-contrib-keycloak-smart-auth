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

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

import java.util.Collections;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class SmartAudienceValidatorFactory implements AuthenticatorFactory {

	/** At most 36 characters: AUTHENTICATION_EXECUTION.AUTHENTICATOR is VARCHAR(36). */
	public static final String ID = "smart-audience-validator";

	public static final String CONFIG_ALLOWED_AUDIENCES = "smart_allowed_audiences";

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.DISABLED
	};

	private static final SmartAudienceValidator SINGLETON = new SmartAudienceValidator();

	@Override
	public String getDisplayType() {
		return "SMART Audience Validator";
	}

	@Override
	public String getReferenceCategory() {
		return "Smart Launch";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		// ALTERNATIVE is absent: a check another execution can bypass is not a check.
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return "Rejects an authorization request whose 'aud' parameter does not name a permitted FHIR server, as required by SMART App Launch 2.x. Fails closed when unconfigured.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return Collections.singletonList(new ProviderConfigProperty(CONFIG_ALLOWED_AUDIENCES,
				"Allowed FHIR audiences",
				"Whitespace- or comma-separated list of permitted 'aud' values, each the base URL of a FHIR server, for example https://openmrs.example.org/openmrs/ws/fhir2/R4. A single trailing slash is ignored; matching is otherwise exact.",
				STRING_TYPE, null));
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope scope) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return ID;
	}
}
