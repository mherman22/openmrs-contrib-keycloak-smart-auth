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

import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Validates the {@code aud} SMART App Launch 2.x requires, so a token minted for one FHIR server is
 * not replayable against another trusting the same realm. Exact matching; unconfigured rejects all.
 */
public class SmartAudienceValidator implements Authenticator {

	private static final Logger logger = Logger.getLogger(SmartAudienceValidator.class);

	/**
	 * Keycloak copies unrecognised authorization-endpoint query parameters into client notes under
	 * this prefix.
	 */
	public static final String CLIENT_REQUEST_PARAM_PREFIX = "client_request_param_";

	/**
	 * {@code aud} is what SMART specifies; {@code resource} and {@code audience} are the RFC 8707
	 * equivalents, which real clients have been seen sending.
	 */
	static final List<String> AUDIENCE_PARAMS = Arrays.asList("aud", "resource", "audience");

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		final List<String> allowed = configuredAudiences(context);

		if (allowed.isEmpty()) {
			// Fail closed: an unconfigured validator must not wave requests through.
			reject(context, "No allowed FHIR audience is configured for this authenticator");
			return;
		}

		final String presented = presentedAudience(context.getAuthenticationSession());

		if (StringUtils.isBlank(presented)) {
			reject(context, "SMART App Launch requires an 'aud' parameter naming the FHIR server");
			return;
		}

		if (!allowed.contains(normalize(presented))) {
			reject(context, "The 'aud' parameter does not name a permitted FHIR server");
			return;
		}

		context.success();
	}

	/**
	 * Reads the audience the client presented, preferring {@code aud} and falling back to the
	 * recognised aliases in order.
	 */
	private String presentedAudience(AuthenticationSessionModel authSession) {
		if (authSession == null) {
			return null;
		}

		for (String param : AUDIENCE_PARAMS) {
			String value = authSession.getClientNote(CLIENT_REQUEST_PARAM_PREFIX + param);
			if (StringUtils.isNotBlank(value)) {
				return value;
			}
		}

		return null;
	}

	/**
	 * The configured audiences, normalised. Whitespace and newlines both separate entries so the
	 * value reads sensibly in the admin console's multi-line field.
	 */
	private List<String> configuredAudiences(AuthenticationFlowContext context) {
		final List<String> audiences = new ArrayList<>();

		if (context.getAuthenticatorConfig() == null || context.getAuthenticatorConfig().getConfig() == null) {
			return audiences;
		}

		String configured = context.getAuthenticatorConfig().getConfig()
				.get(SmartAudienceValidatorFactory.CONFIG_ALLOWED_AUDIENCES);

		if (StringUtils.isBlank(configured)) {
			return audiences;
		}

		for (String candidate : configured.split("[\\s,]+")) {
			String normalized = normalize(candidate);
			if (normalized != null) {
				audiences.add(normalized);
			}
		}

		return audiences;
	}

	/**
	 * Trims whitespace and one trailing slash, so a FHIR base matches however it was written.
	 * Otherwise exact, including case.
	 */
	private String normalize(String audience) {
		if (StringUtils.isBlank(audience)) {
			return null;
		}

		String trimmed = audience.trim();
		return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
	}

	private void reject(AuthenticationFlowContext context, String reason) {
		// Logged rather than EventBuilder.error, which expects an Errors constant and fires itself.
		logger.warnf("Rejecting SMART authorization request: %s", reason);
		context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
				context.form().setError(Messages.INVALID_REQUEST).createErrorPage(Response.Status.BAD_REQUEST));
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// Nothing is submitted back to this authenticator; validation happens up front.
		authenticate(context);
	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}
}
