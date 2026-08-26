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

import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.crypto.spec.SecretKeySpec;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class SmartLaunchAccessAuthenticator implements Authenticator {

	public static final String QUERY_PARAM_APP_TOKEN = "app_token";

	public static final String SMART_ACCESS = "smart_access";

	public static final String DEFAULT_PATIENT_ACCESS_URL = "http://localhost:8080/openmrs/smartonfhir/smartAccessConfirmation?token={TOKEN}&launch={launchUuid}";

	private static final Logger logger = Logger.getLogger(SmartLaunchAccessAuthenticator.class);

	/**
	 * Hands the browser to OpenMRS to say who is signed in, returning to this same execution. Not a
	 * Keycloak action token: those name a user, and an EHR launch has nobody authenticated yet.
	 */
	@Override
	public void authenticate(AuthenticationFlowContext context) {

		final String launch = context.getAuthenticationSession()
				.getClientNote(SmartLaunchAuthenticator.LAUNCH_CLIENT_REQUEST_PARAM);
		final String scope = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.SCOPE_PARAM);

		if (launch != null && scope != null) {

			String accessEndUrl = null;
			if (context.getAuthenticatorConfig() != null) {
				accessEndUrl = context.getAuthenticatorConfig().getConfig()
						.get(SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_URL);
			}

			if (accessEndUrl == null) {
				accessEndUrl = DEFAULT_PATIENT_ACCESS_URL;
			}

			final AuthenticationSessionModel authSession = context.getAuthenticationSession();

			final String accessCode = context.generateAccessCode();
			final String actionUrl = context.getActionUrl(accessCode).toString();
			final String submitUrl = actionUrl + (actionUrl.contains("?") ? "&" : "?") + QUERY_PARAM_APP_TOKEN
					+ "={APP_TOKEN}";

			// Without this, action() reads the return trip as a fresh attempt and loops.
			authSession.setAuthNote(SMART_ACCESS, "true");

			try {
				Response challenge = Response
						.status(Response.Status.FOUND)
						.header("Location",
								accessEndUrl.replace("{TOKEN}",
										URLEncoder.encode(submitUrl, StandardCharsets.UTF_8.name())).
										replace("{launchUuid}", launch))
						.build();
				context.challenge(challenge);
			}
			catch (UnsupportedEncodingException e) {
				throw new AuthenticationFlowException("Could not decode token", e, AuthenticationFlowError.INTERNAL_ERROR);
			}

			return;
		}

		context.attempted();
	}

	@Override
	public void action(AuthenticationFlowContext context) {

		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		if (!Objects.equals(authSession.getAuthNote(SMART_ACCESS), "true")) {
			authenticate(context);
			return;
		}

		authSession.removeAuthNote(SMART_ACCESS);

		String appTokenString = context.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);

		if (StringUtils.isBlank(appTokenString)) {
			// Nobody is signed in to OpenMRS; reported as attempted so the next alternative runs.
			logger.debugf("No app token returned for realm %s; leaving the launch to the next authenticator",
					context.getRealm().getName());
			context.attempted();
			return;
		}

		JsonWebToken appToken;
		try {
			validateAppToken(context, appTokenString);
			appToken = TokenVerifier.create(appTokenString, JsonWebToken.class).getToken();
		}
		catch (IOException | VerificationException e) {
			context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form()
					.setError(Messages.INVALID_PARAMETER)
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		String username = appToken.getSubject();

		if (username == null) {
			context.attempted();
			return;
		}

		SmartLaunchAuthenticator.writeContextNotes(authSession, appToken.getOtherClaims());

		UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

		if (user == null) {
			// success() here would complete the execution with nobody authenticated, which Keycloak
			// turns into an UNKNOWN_USER error page. Reported as attempted so the login form can run.
			logger.warnf("OpenMRS returned a launch for '%s', which realm %s has no user for; "
					+ "leaving the launch to the next authenticator", username, context.getRealm().getName());
			context.attempted();
			return;
		}

		authSession.setAuthenticatedUser(user);

		context.success();
	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

	}

	@Override
	public void close() {

	}

	/**
	 * The shared secret verifying the token OpenMRS returns, which is itself the authentication here.
	 * No default: a key an attacker also knows would forge any launch.
	 */
	SecretKeySpec getSecretKey(AuthenticatorConfigModel authenticatorConfig, String realmName) throws
			IOException {
		String secretKey = null;
		if (authenticatorConfig != null) {
			secretKey = authenticatorConfig.getConfig()
					.get(SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY);
		}

		if (StringUtils.isBlank(secretKey)) {
			logger.warnf("Refusing to verify a SMART launch token: %s is not configured for realm %s",
					SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY, realmName);
			throw new AuthenticationFlowException("Secret key is not configured for realm " + realmName,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		return new SecretKeySpec(Base64.decode(secretKey), JavaAlgorithm.HS256);
	}

	private void validateAppToken(AuthenticationFlowContext context, String appTokenString)
			throws VerificationException, IOException {
		TokenVerifier.create(appTokenString, JsonWebToken.class)
				.secretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getName()))
				.verify();
	}
}
