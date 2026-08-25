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
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.jboss.logging.Logger;
import org.openmrs.contrib.keycloak.smart.auth.token.SmartPatientSelectionActionToken;
import org.openmrs.contrib.keycloak.smart.auth.token.SmartUserNameToken;

import static org.keycloak.OAuth2Constants.JWT;

public class SmartLaunchAuthenticator implements Authenticator {

	public static final String QUERY_PARAM_APP_TOKEN = "app_token";

	public static final String SMART_PATIENT_SELECTION = "smart_patient_selection";

	public static final String SMART_NOTE_PREFIX = "smart-oidc-note.";

	/**
	 * The context a launch can establish. All of these are written on every launch, blank included,
	 * because the notes outlive one launch and a stale visit would belong to another patient.
	 */
	static final List<String> CONTEXT_NOTES = Arrays.asList("patient", "visit", "fhirUser");

	public static final String DEFAULT_PATIENT_SELECTION_APP_URL = "http://localhost:8080/openmrs/smartonfhir/findPatient.page?app=smart.search&token={TOKEN}";

	public static final String LAUNCH_SCOPE_PREFIX = "launch/";

	public static final String LAUNCH_CLIENT_REQUEST_PARAM = "client_request_param_launch";

	private static final Logger logger = Logger.getLogger(SmartLaunchAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		final String launchContext = context.getAuthenticationSession().getClientNote(LAUNCH_CLIENT_REQUEST_PARAM);
		if (!StringUtils.isEmpty(launchContext)) {
			context.success();
			return;
		} else {
			selectPatient(context);
		}
	}

	private void selectPatient(AuthenticationFlowContext context) {
		String patientSelectionUrl = null;
		if (context.getAuthenticatorConfig() != null) {
			patientSelectionUrl = context.getAuthenticatorConfig().getConfig()
					.get(SmartLaunchAuthenticatorFactory.CONFIG_SMART_PATIENT_SELECTION_URL);
		}

		if (patientSelectionUrl == null) {
			patientSelectionUrl = DEFAULT_PATIENT_SELECTION_APP_URL;
		}

		String scope = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.SCOPE_PARAM);
		Map<String, ClientScopeModel> defaultScopes = context.getAuthenticationSession().getClient()
				.getClientScopes(true);

		if (scope == null) {
			scope = "";
		}

		List<String> scopes = Arrays.stream(scope.split("\\s+")).collect(Collectors.toList());
		String supportedParams = context.getAuthenticatorConfig().getConfig()
				.get(SmartLaunchAuthenticatorFactory.CONFIG_EXTERNAL_SMART_LAUNCH_SUPPORTED_PARAMS);
		if (supportedParams == null || supportedParams.isEmpty()) {
			context.attempted();
			return;
		}

		List<String> params = Arrays.stream(supportedParams.split("\\s+")).collect(Collectors.toList());
		boolean foundMatch = false;
		for (String param : params) {
			if (scopes.contains(LAUNCH_SCOPE_PREFIX + param) ||
					defaultScopes.containsKey(LAUNCH_SCOPE_PREFIX + param)) {
				foundMatch = true;
			}
		}

		if (!foundMatch) {
			context.success();
			return;
		}

		int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
		int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		final String clientId = authSession.getClient().getClientId();

		// Create a token used to return back to the current authentication flow
		SmartPatientSelectionActionToken externalToken = new SmartPatientSelectionActionToken(
				context.getUser().getId(),
				absoluteExpirationInSecs,
				AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId()
		);

		try {
			externalToken
					.setNote("user", buildUserNameToken(context, absoluteExpirationInSecs, clientId, patientSelectionUrl));
			externalToken.setOtherClaims("launchType", getLaunchScopes(scope));
		}
		catch (IOException e) {
			throw new AuthenticationFlowException("Could not create user token", e, AuthenticationFlowError.INTERNAL_ERROR);
		}

		String token = externalToken.serialize(
				context.getSession(),
				context.getRealm(),
				context.getUriInfo()
		);

		// This URL will be used by the application to submit the action token above to return back to the flow
		String submitActionTokenUrl = Urls
				.actionTokenBuilder(context.getUriInfo().getBaseUri(), token, clientId, authSession.getTabId(), null)
				.queryParam(Constants.EXECUTION, context.getExecution().getId())
				.queryParam(QUERY_PARAM_APP_TOKEN, "{tokenParameterName}")
				.build(context.getRealm().getName(), "{APP_TOKEN}")
				.toString();

		try {
			Response challenge = Response
					.status(Status.FOUND)
					.header("Location",
							patientSelectionUrl.replace("{TOKEN}",
									URLEncoder.encode(submitActionTokenUrl, StandardCharsets.UTF_8.name())))
					.build();
			context.challenge(challenge);
		}
		catch (UnsupportedEncodingException e) {
			throw new AuthenticationFlowException("Could not decode token", e, AuthenticationFlowError.INTERNAL_ERROR);
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		if (!Objects.equals(authSession.getAuthNote(SMART_PATIENT_SELECTION), "true")) {
			authenticate(context);
			return;
		}

		authSession.removeAuthNote(SMART_PATIENT_SELECTION);

		String appTokenString = context.getUriInfo().getQueryParameters().getFirst(QUERY_PARAM_APP_TOKEN);

		if (StringUtils.isBlank(appTokenString)) {
			// try again
			authenticate(context);
			return;
		}

		JsonWebToken appToken;
		try {
			validateAppToken(context, appTokenString);
			appToken = TokenVerifier.create(appTokenString, JsonWebToken.class).getToken();
		}
		catch (IOException | VerificationException e) {
			logger.error("Error handling action token", e);
			context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form()
					.setError(Messages.INVALID_PARAMETER)
					.createErrorPage(Status.INTERNAL_SERVER_ERROR));
			return;
		}

		writeContextNotes(authSession, appToken.getOtherClaims());

		context.success();
	}

	/**
	 * Writes the launch context onto the authentication session for the claim mapper. Every
	 * {@link #CONTEXT_NOTES} entry is written, so nothing survives from a previous launch.
	 */
	static void writeContextNotes(AuthenticationSessionModel authSession, Map<String, Object> claims) {
		for (String note : CONTEXT_NOTES) {
			Object value = claims.get(note);
			authSession.setUserSessionNote(SMART_NOTE_PREFIX + note, value instanceof String ? (String) value : "");
		}

		claims.forEach((key, value) -> {
			if (value instanceof String && !CONTEXT_NOTES.contains(key)) {
				authSession.setUserSessionNote(SMART_NOTE_PREFIX + key, (String) value);
			}
		});
	}

	@Override
	public boolean requiresUser() {
		return true;
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

	private String buildUserNameToken(AuthenticationFlowContext context, int absoluteExpirationInSecs, String clientId,
			String patientSelectionUrl) throws IOException {
		// Says the user pre-authenticated with Keycloak, so OpenMRS can sign them in to pick a patient.
		UserModel user = context.getUser();
		String userName = user == null ? null : user.getUsername();

		if (userName == null || userName.trim().isEmpty()) {
			throw new AuthenticationFlowException(
					"A standalone launch reached patient selection with no username for user "
							+ (user == null ? "(none authenticated)" : user.getId())
							+ "; refusing to issue a launch token OpenMRS cannot attribute",
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		SmartUserNameToken userToken = new SmartUserNameToken(
				userName,
				absoluteExpirationInSecs,
				clientId
		);

		String issuer = Urls.realmIssuer(context.getUriInfo().getBaseUri(), context.getRealm().getName());
		userToken.issuer(issuer);

		URL usernameAudienceUrl;
		try {
			usernameAudienceUrl = new URL(patientSelectionUrl);
		}
		catch (MalformedURLException e) {
			throw new AuthenticationFlowException("Could not parse external URL " + patientSelectionUrl, e,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		userToken.audience(SmartUserNameToken.audienceFor(usernameAudienceUrl));

		// sign the token with a shared secret so it can be verified by the client
		KeyWrapper key = new KeyWrapper();
		key.setAlgorithm(Algorithm.HS256);
		key.setSecretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getDisplayName()));
		SignatureSignerContext signer = new MacSignatureSignerContext(key);

		return new JWSBuilder().type(JWT).jsonContent(userToken).sign(signer);
	}

	private void validateAppToken(AuthenticationFlowContext context, String appTokenString)
			throws VerificationException, IOException {
		TokenVerifier.create(appTokenString, JsonWebToken.class)
				.secretKey(getSecretKey(context.getAuthenticatorConfig(), context.getRealm().getDisplayName()))
				.verify();
	}

	/**
	 * The shared secret signing the token sent to OpenMRS and verifying the one it returns. No default:
	 * anything able to sign with it can assert any username to Keycloak without a password.
	 */
	SecretKeySpec getSecretKey(AuthenticatorConfigModel authenticatorConfig, String realmName) throws IOException {
		String secretKey = null;

		if (authenticatorConfig != null) {
			secretKey = authenticatorConfig.getConfig()
					.get(SmartLaunchAuthenticatorFactory.CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY);
		}

		if (StringUtils.isBlank(secretKey)) {
			logger.warnf("Refusing to sign or verify a SMART launch token: %s is not configured for realm %s",
					SmartLaunchAuthenticatorFactory.CONFIG_EXTERNAL_SMART_LAUNCH_SECRET_KEY, realmName);
			throw new AuthenticationFlowException("Secret key is not configured for realm " + realmName,
					AuthenticationFlowError.INTERNAL_ERROR);
		}

		return new SecretKeySpec(Base64.decode(secretKey), JavaAlgorithm.HS256);
	}

	/**
	 * Extracts the context types from any {@code launch/*} scopes, so {@code "openid launch/patient"}
	 * yields {@code "patient"}. Package-private for testing.
	 */
	String getLaunchScopes(String scope) {
		if (scope == null) {
			return "";
		}

		return Arrays.stream(scope.split("\\s+")).filter(it -> it.startsWith(LAUNCH_SCOPE_PREFIX))
				.map(it -> it.substring(LAUNCH_SCOPE_PREFIX.length())).filter(StringUtils::isNotBlank)
				.collect(Collectors.joining(" "));
	}
}
