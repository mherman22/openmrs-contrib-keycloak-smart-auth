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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.RuntimeDelegate;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.MacSignatureSignerContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The EHR launch: OpenMRS says who is already signed in and Keycloak takes its word for it, so which
 * user the flow ends up as, and whether it ends up as anyone at all, is the whole of the security here.
 */
@ExtendWith(MockitoExtension.class)
public class SmartLaunchAccessAuthenticatorTest {

	/** "smart-launch-secret" base64-encoded. */
	private static final String SECRET = "c21hcnQtbGF1bmNoLXNlY3JldA==";

	private static final String OTHER_SECRET = "YW5vdGhlci1zZWNyZXQtZW50aXJlbHk=";

	private static final String CLINICIAN = "jdoe";

	private static final String LAUNCH_ID = "9c8b7a65-4321-4321-8765-0123456789ab";

	private static final String PATIENT_UUID = "6a1b2c3d-0000-4444-8888-abcdefabcdef";

	private static final String ACCESS_URL = "https://openmrs.example.org/openmrs/smartonfhir/smartAccessConfirmation"
			+ "?token={TOKEN}&launch={launchUuid}";

	private static final String ACTION_URL = "https://kc.example.org/realms/openmrs/login-actions/authenticate"
			+ "?session_code=abc&execution=xyz";

	@Mock
	private AuthenticationFlowContext context;

	@Mock
	private AuthenticationSessionModel authSession;

	@Mock
	private RealmModel realm;

	@Mock
	private KeycloakSession session;

	@Mock
	private UserProvider users;

	@Mock
	private UriInfo uriInfo;

	@Mock
	private UserModel user;

	private SmartLaunchAccessAuthenticator authenticator;

	private Map<String, String> authNotes;

	private Map<String, String> clientNotes;

	private Map<String, String> userSessionNotes;

	private MultivaluedMap<String, String> queryParameters;

	private Response.ResponseBuilder responseBuilder;

	@BeforeEach
	public void setUp() {
		authenticator = new SmartLaunchAccessAuthenticator();
		authNotes = new HashMap<>();
		clientNotes = new HashMap<>();
		userSessionNotes = new HashMap<>();
		queryParameters = new MultivaluedHashMap<>();

		lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
		lenient().when(context.getRealm()).thenReturn(realm);
		lenient().when(context.getSession()).thenReturn(session);
		lenient().when(context.getUriInfo()).thenReturn(uriInfo);
		lenient().when(session.users()).thenReturn(users);
		lenient().when(uriInfo.getQueryParameters()).thenReturn(queryParameters);
		lenient().when(realm.getName()).thenReturn("openmrs");
		lenient().when(realm.getDisplayName()).thenReturn("OpenMRS");
		lenient().when(context.getAuthenticatorConfig()).thenReturn(config(SECRET));

		lenient().when(authSession.getAuthNote(anyString())).thenAnswer(inv -> authNotes.get(inv.getArgument(0)));
		lenient().when(authSession.getClientNote(anyString())).thenAnswer(inv -> clientNotes.get(inv.getArgument(0)));
		lenient().doAnswer(inv -> authNotes.put(inv.getArgument(0), inv.getArgument(1))).when(authSession)
				.setAuthNote(anyString(), anyString());
		lenient().doAnswer(inv -> authNotes.remove(inv.getArgument(0))).when(authSession).removeAuthNote(anyString());
		lenient().doAnswer(inv -> userSessionNotes.put(inv.getArgument(0), inv.getArgument(1))).when(authSession)
				.setUserSessionNote(anyString(), any());

		// The error path renders a form; Response.status() needs the delegate stubbed below.
		LoginFormsProvider forms = mock(LoginFormsProvider.class);
		lenient().when(context.form()).thenReturn(forms);
		lenient().when(forms.setError(anyString())).thenReturn(forms);
		lenient().when(forms.createErrorPage(any())).thenReturn(mock(Response.class));

		// Only jakarta.ws.rs-api is on the test classpath, so Response.status(...) has no delegate to
		// build with. Stubbing one is what makes the redirect this authenticator issues observable.
		responseBuilder = mock(Response.ResponseBuilder.class);
		lenient().when(responseBuilder.status(any(Response.StatusType.class))).thenReturn(responseBuilder);
		lenient().when(responseBuilder.header(anyString(), any())).thenReturn(responseBuilder);
		lenient().when(responseBuilder.build()).thenReturn(mock(Response.class));
		RuntimeDelegate delegate = mock(RuntimeDelegate.class);
		lenient().when(delegate.createResponseBuilder()).thenReturn(responseBuilder);
		RuntimeDelegate.setInstance(delegate);
	}

	@AfterEach
	public void tearDown() {
		RuntimeDelegate.setInstance(null);
	}

	private static AuthenticatorConfigModel config(String secret) {
		AuthenticatorConfigModel config = new AuthenticatorConfigModel();
		Map<String, String> values = new HashMap<>();
		values.put(SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_SECRET_KEY, secret);
		values.put(SmartLaunchAccessAuthenticatorFactory.CONFIG_SMART_LAUNCH_ACCESS_URL, ACCESS_URL);
		config.setConfig(values);
		return config;
	}

	/** A token shaped like the one the OpenMRS module signs and returns. */
	private static String appToken(String subject, Map<String, Object> claims, String secret) throws Exception {
		JsonWebToken token = new JsonWebToken();
		token.subject(subject);
		token.exp((long) Time.currentTime() + 60);
		claims.forEach(token::setOtherClaims);

		KeyWrapper key = new KeyWrapper();
		key.setAlgorithm(Algorithm.HS256);
		key.setSecretKey(new SecretKeySpec(Base64.decode(secret), JavaAlgorithm.HS256));

		return new JWSBuilder().type("JWT").jsonContent(token).sign(new MacSignatureSignerContext(key));
	}

	/** Puts the flow in the state the return trip from OpenMRS arrives in. */
	private void returningFromOpenmrs(String appTokenString) {
		authNotes.put(SmartLaunchAccessAuthenticator.SMART_ACCESS, "true");
		if (appTokenString != null) {
			queryParameters.putSingle(SmartLaunchAccessAuthenticator.QUERY_PARAM_APP_TOKEN, appTokenString);
		}
	}

	@Nested
	public class HandingTheBrowserToOpenmrs {

		private void launchRequested() {
			clientNotes.put(SmartLaunchAuthenticator.LAUNCH_CLIENT_REQUEST_PARAM, LAUNCH_ID);
			clientNotes.put(OIDCLoginProtocol.SCOPE_PARAM, "openid launch fhirUser");
			lenient().when(context.generateAccessCode()).thenReturn("abc");
			lenient().when(context.getActionUrl(anyString())).thenReturn(URI.create(ACTION_URL));
		}

		private String redirectLocation() {
			ArgumentCaptor<Object> location = ArgumentCaptor.forClass(Object.class);
			verify(responseBuilder).header(eq("Location"), location.capture());
			return String.valueOf(location.getValue());
		}

		/**
		 * The launch id has to reach OpenMRS, or it cannot tell which launch is being confirmed.
		 */
		@Test
		public void authenticate_shouldSendTheBrowserToOpenmrsWithTheLaunchId() {
			launchRequested();

			authenticator.authenticate(context);

			verify(context).challenge(any());
			assertTrue(redirectLocation().contains("launch=" + LAUNCH_ID),
					"the launch id must reach OpenMRS: " + redirectLocation());
		}

		/**
		 * OpenMRS appends the token it signs where the placeholder is, so the return URL has to arrive
		 * carrying {@code app_token={APP_TOKEN}} for it to substitute.
		 */
		@Test
		public void authenticate_shouldGiveOpenmrsAReturnUrlWithAPlaceholderForItsToken() throws Exception {
			launchRequested();

			authenticator.authenticate(context);

			String returnUrl = URLDecoder.decode(redirectLocation(), StandardCharsets.UTF_8.name());
			assertTrue(returnUrl.contains(ACTION_URL), "the return URL should be this execution's action URL: "
					+ returnUrl);
			assertTrue(returnUrl.contains(SmartLaunchAccessAuthenticator.QUERY_PARAM_APP_TOKEN + "={APP_TOKEN}"),
					"OpenMRS substitutes its signed token for {APP_TOKEN}: " + returnUrl);
		}

		/**
		 * An EHR launch has nobody authenticated yet. Minting an action token for the literal username
		 * {@code admin} was how this used to satisfy the action-token endpoint, and it fails on a stock
		 * OpenMRS database where the administrator's username column is NULL.
		 */
		@Test
		public void authenticate_shouldNotLookUpAnyUserToHandTheBrowserOver() {
			launchRequested();

			authenticator.authenticate(context);

			verifyNoInteractions(users);
		}

		@Test
		public void authenticate_shouldMarkTheReturnTripSoItIsNotReadAsAFreshAttempt() {
			launchRequested();

			authenticator.authenticate(context);

			assertEquals("true", authNotes.get(SmartLaunchAccessAuthenticator.SMART_ACCESS));
		}

		@Test
		public void authenticate_shouldPassOverARequestThatIsNotAnEhrLaunch() {
			clientNotes.put(OIDCLoginProtocol.SCOPE_PARAM, "openid");

			authenticator.authenticate(context);

			verify(context).attempted();
			verify(context, never()).challenge(any());
		}
	}

	@Nested
	public class TakingOpenmrsWordForWhoIsSignedIn {

		@Test
		public void action_shouldAuthenticateTheUserTheReturnedTokenNames() throws Exception {
			returningFromOpenmrs(appToken(CLINICIAN, new HashMap<>(), SECRET));
			lenient().when(users.getUserByUsername(realm, CLINICIAN)).thenReturn(user);

			authenticator.action(context);

			verify(users).getUserByUsername(realm, CLINICIAN);
			verify(authSession).setAuthenticatedUser(user);
			verify(context).success();
		}

		@Test
		public void action_shouldPutTheReturnedLaunchContextWhereTheClaimMapperReadsIt() throws Exception {
			Map<String, Object> claims = new HashMap<>();
			claims.put("patient", PATIENT_UUID);
			claims.put("fhirUser", "Practitioner/" + PATIENT_UUID);
			returningFromOpenmrs(appToken(CLINICIAN, claims, SECRET));
			lenient().when(users.getUserByUsername(realm, CLINICIAN)).thenReturn(user);

			authenticator.action(context);

			assertEquals(PATIENT_UUID, userSessionNotes.get(SmartLaunchAuthenticator.SMART_NOTE_PREFIX + "patient"));
			assertEquals("Practitioner/" + PATIENT_UUID,
					userSessionNotes.get(SmartLaunchAuthenticator.SMART_NOTE_PREFIX + "fhirUser"));
		}

		/**
		 * The notes outlive one launch, so a launch that establishes no visit must overwrite the note
		 * rather than leave the previous launch's visit standing under this patient.
		 */
		@Test
		public void action_shouldClearTheContextALaunchDoesNotEstablish() throws Exception {
			Map<String, Object> claims = new HashMap<>();
			claims.put("patient", PATIENT_UUID);
			returningFromOpenmrs(appToken(CLINICIAN, claims, SECRET));
			lenient().when(users.getUserByUsername(realm, CLINICIAN)).thenReturn(user);

			authenticator.action(context);

			assertEquals("", userSessionNotes.get(SmartLaunchAuthenticator.SMART_NOTE_PREFIX + "visit"),
					"a visit left over from an earlier launch would belong to another patient");
		}
	}

	@Nested
	public class RefusingToVouch {

		/**
		 * A clinician OpenMRS knows and this realm does not. success() here would complete the execution
		 * with nobody authenticated, which Keycloak turns into an UNKNOWN_USER error page instead of
		 * letting the login form run.
		 */
		@Test
		public void action_shouldFallThroughWhenTheRealmHasNoUserForTheTokensSubject() throws Exception {
			returningFromOpenmrs(appToken(CLINICIAN, new HashMap<>(), SECRET));
			lenient().when(users.getUserByUsername(realm, CLINICIAN)).thenReturn(null);

			authenticator.action(context);

			verify(context).attempted();
			verify(context, never()).success();
			verify(authSession, never()).setAuthenticatedUser(any());
		}

		@Test
		public void action_shouldFallThroughWhenNobodyIsSignedInToOpenmrs() {
			returningFromOpenmrs(null);

			authenticator.action(context);

			verify(context).attempted();
			verify(context, never()).success();
		}

		@Test
		public void action_shouldFallThroughWhenTheReturnedTokenNamesNobody() throws Exception {
			returningFromOpenmrs(appToken(null, new HashMap<>(), SECRET));

			authenticator.action(context);

			verify(context).attempted();
			verify(context, never()).success();
		}

		/** The signature is the authentication: a token signed with anything else asserts nothing. */
		@Test
		public void action_shouldRefuseATokenSignedWithAnotherSecret() throws Exception {
			returningFromOpenmrs(appToken(CLINICIAN, new HashMap<>(), OTHER_SECRET));

			authenticator.action(context);

			verify(context).failure(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
			verify(context, never()).success();
			verify(authSession, never()).setAuthenticatedUser(any());
		}

		/**
		 * The realm's display name is optional in Keycloak and unset in the realm this plugin ships
		 * against, so a fail-closed message that named the realm by it would name no realm at all on the
		 * deployment it matters for. setUp() stubs the two apart on purpose: this reads "openmrs".
		 */
		@Test
		public void action_shouldNameTheRealmByItsNameWhenNoSecretIsConfigured() throws Exception {
			when(context.getAuthenticatorConfig()).thenReturn(null);
			returningFromOpenmrs(appToken(CLINICIAN, new HashMap<>(), SECRET));

			AuthenticationFlowException thrown = assertThrows(AuthenticationFlowException.class,
					() -> authenticator.action(context));

			assertTrue(thrown.getMessage().endsWith("realm openmrs"),
					"the fail-closed message should name the realm by getName(); got: " + thrown.getMessage());
		}
	}
}
