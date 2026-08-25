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

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.PASSWORD;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class SmartLaunchAuthenticatorFactory implements AuthenticatorFactory {

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.ALTERNATIVE,
			AuthenticationExecutionModel.Requirement.DISABLED
	};

	public static final String CONFIG_SMART_PATIENT_SELECTION_URL = "smart_patient_selection_url";

	public static final String CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY = "smart_launch_secret_key";

	public static final String CONFIG_EXTERNAL_SMART_LAUNCH_SUPPORTED_PARAMS = "smart_launch_supported_params";

	public static final String ID = "smart-application-authenticator";

	public static final SmartLaunchAuthenticator SINGLETON = new SmartLaunchAuthenticator();

	@Override
	public String getDisplayType() {
		return "Smart Application Authenticator";
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
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return "External Application Authenticator";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		ProviderConfigProperty patientSelectionUrl = new ProviderConfigProperty(CONFIG_SMART_PATIENT_SELECTION_URL,
				"Patient Selection Application URL",
				"URL of the application to redirect to. It has to contain token position marked with \"{TOKEN}\" (without quotes).",
				STRING_TYPE, SmartLaunchAuthenticator.DEFAULT_PATIENT_SELECTION_APP_URL);

		// No default: "" would advertise itself as a usable key.
		ProviderConfigProperty smartLaunchKey = new ProviderConfigProperty(CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY,
				"External SMART Launch Secret Key",
				"Base64-encoded HmacSHA256 secret key shared with the OpenMRS SMART on FHIR module. Required: an unconfigured authenticator rejects every launch.",
				PASSWORD, null);

		ProviderConfigProperty smartLaunchSupportedParams = new ProviderConfigProperty(
				CONFIG_EXTERNAL_SMART_LAUNCH_SUPPORTED_PARAMS,
				"External SMART Launch Supported Params",
				"Space separated list of Smart launch context parameters supported by external application.",
				ProviderConfigProperty.STRING_TYPE, null);

		return Arrays.asList(patientSelectionUrl, smartLaunchKey, smartLaunchSupportedParams);
	}

	@Override
	public Authenticator create(KeycloakSession keycloakSession) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope scope) {
	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return ID;
	}
}
