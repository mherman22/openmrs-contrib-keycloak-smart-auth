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
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.MacSignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.openmrs.contrib.keycloak.smart.auth.token.SmartUserNameToken;

import javax.crypto.spec.SecretKeySpec;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

import static org.keycloak.OAuth2Constants.JWT;
import static org.openmrs.contrib.keycloak.smart.auth.provider.SmartLaunchAuthenticator.SMART_NOTE_PREFIX;

public class SmartLaunchAccessAuthenticator implements Authenticator {

	public static final String QUERY_PARAM_APP_TOKEN = "app-token";

	public static final String SMART_ACCESS = "smart-access";

	public static final String DEFAULT_PATIENT_ACCESS_URL = "http://localhost:8080/openmrs/smartonfhir/smartAccessConfirmation?token={TOKEN}&launch={launchUuid}";

	private static final Logger logger = Logger.getLogger(SmartLaunchAccessAuthenticator.class);

	/**
	 * Hands the browser to OpenMRS so that the EHR can say who is signed in, and comes back into this
	 * same execution with the answer.
	 * <p>
	 * This deliberately does not use a Keycloak action token. An EHR launch has nobody authenticated
	 * yet, and the action-token endpoint requires the token to name a user. Naming the literal username
	 * {@code admin} to satisfy it fails on a stock OpenMRS database, where the administrator's
	 * {@code username} column is NULL and {@code admin} is its {@code system_id}, so every EHR launch
	 * died at the authorization endpoint. The execution's own action URL is bound to the authentication
	 * session and needs no user.
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

			int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
			int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
			final AuthenticationSessionModel authSession = context.getAuthenticationSession();
			final String clientId = authSession.getClient().getClientId();

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
			authenticate(context);
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
		context.getAuthenticationSession().setAuthenticatedUser(user);

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

	private String buildUserNameToken(AuthenticationFlowContext context, int absoluteExpirationInSecs, String clientId,
			String accessUrl) throws IOException {

		SmartUserNameToken userToken = new SmartUserNameToken(
				absoluteExpirationInSecs,
				clientId
		);

		String issuer = Urls.realmIssuer(context.getUriInfo().getBaseUri(), context.getRealm().getName());
		userToken.issuer(issuer);

		URL usernameAudienceUrl;
		try {
			usernameAudienceUrl = new URL(accessUrl);
		}
		catch (MalformedURLException e) {
			throw new AuthenticationFlowException("Could not parse external URL " + accessUrl, e,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		StringBuilder sb = new StringBuilder(usernameAudienceUrl.getProtocol()).append("://")
				.append(usernameAudienceUrl.getHost());
		if (usernameAudienceUrl.getPort() != usernameAudienceUrl.getDefaultPort()) {
			sb.append(":").append(usernameAudienceUrl.getPort());
		}
		userToken.audience(sb.toString());

		KeyWrapper key = new KeyWrapper();
		key.setAlgorithm(Algorithm.HS256);
		key.setSecretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getName()));
		SignatureSignerContext signer = new MacSignatureSignerContext(key);

		return new JWSBuilder().type(JWT).jsonContent(userToken).sign(signer);
	}

	/**
	 * The shared secret that signs the token sent to OpenMRS and verifies the one it returns. On this
	 * authenticator that returned token <em>is</em> the authentication: {@link #action} takes its
	 * subject as the signed-in clinician and no password is ever presented. Fails closed when
	 * unconfigured, as {@link SmartAudienceValidator} does and for the same reason: an empty or
	 * defaulted key is one an attacker also knows, and would let anyone forge the EHR launch. There is
	 * deliberately no default.
	 * <p>
	 * Package-private so the fail-closed path can be tested.
	 */
	SecretKeySpec getSecretKey(AuthenticatorConfigModel authenticatorConfig, String realmName) throws
			IOException {
		String secretKey = null;
		if (authenticatorConfig != null) {
			secretKey = authenticatorConfig.getConfig()
					.get(SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY);
		}

		if (StringUtils.isBlank(secretKey)) {
			logger.warnf("Refusing to sign or verify a SMART launch token: %s is not configured for realm %s",
					SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY, realmName);
			throw new AuthenticationFlowException("Secret key is not configured for realm " + realmName,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		return new SecretKeySpec(Base64.decode(secretKey), JavaAlgorithm.HS256);
	}

	private void validateAppToken(AuthenticationFlowContext context, String appTokenString)
			throws VerificationException, IOException {
		TokenVerifier.create(appTokenString, JsonWebToken.class)
				.secretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getDisplayName()))
				.verify();
	}
}
