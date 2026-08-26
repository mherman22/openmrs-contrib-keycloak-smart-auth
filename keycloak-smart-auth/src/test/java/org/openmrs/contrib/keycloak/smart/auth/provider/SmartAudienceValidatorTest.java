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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The audience check is all that stops a token minted for one FHIR server being replayed against
 * another trusting the same realm, so what it rejects matters as much as what it accepts.
 */
@ExtendWith(MockitoExtension.class)
public class SmartAudienceValidatorTest {

	private static final String FHIR_BASE = "https://openmrs.example.org/openmrs/ws/fhir2/R4";

	private static final String OTHER_FHIR_BASE = "https://other.example.org/fhir";

	@Mock
	private AuthenticationFlowContext context;

	@Mock
	private AuthenticationSessionModel authSession;

	private SmartAudienceValidator validator;

	private Map<String, String> clientNotes;

	@BeforeEach
	public void setUp() {
		validator = new SmartAudienceValidator();
		clientNotes = new HashMap<>();

		lenient().when(context.getAuthenticationSession()).thenReturn(authSession);
		lenient().when(authSession.getClientNote(anyString())).thenAnswer(inv -> clientNotes.get(inv.getArgument(0)));

		// The error path renders a form; stubbed loosely so failures point at the decision under test.
		LoginFormsProvider forms = mock(LoginFormsProvider.class);
		lenient().when(context.form()).thenReturn(forms);
		lenient().when(forms.setError(anyString())).thenReturn(forms);
		// Mocked, since Response.status() needs a RuntimeDelegate and only the API is on the classpath.
		lenient().when(forms.createErrorPage(any())).thenReturn(mock(Response.class));
	}

	private void configureAllowed(String allowed) {
		AuthenticatorConfigModel config = new AuthenticatorConfigModel();
		Map<String, String> cfg = new HashMap<>();
		cfg.put(SmartAudienceValidatorFactory.CONFIG_ALLOWED_AUDIENCES, allowed);
		config.setConfig(cfg);
		when(context.getAuthenticatorConfig()).thenReturn(config);
	}

	private void present(String param, String value) {
		clientNotes.put(SmartAudienceValidator.CLIENT_REQUEST_PARAM_PREFIX + param, value);
	}

	/**
	 * The shape a parameter Keycloak recognises actually arrives in: a plain client note under the
	 * parameter's own name, with no prefix. {@code resource} is such a parameter.
	 */
	private void presentPlain(String param, String value) {
		clientNotes.put(param, value);
	}

	/** Asserts the request was rejected, and that it was rejected rather than merely not accepted. */
	private void assertRejected() {
		verify(context, never()).success();
		ArgumentCaptor<AuthenticationFlowError> error = ArgumentCaptor.forClass(AuthenticationFlowError.class);
		verify(context).failure(error.capture(), any());
		assertEquals(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, error.getValue(),
				"rejection should be reported as invalid client credentials");
	}

	private void assertAccepted() {
		verify(context).success();
		verify(context, never()).failure(any(), any());
	}

	@Nested
	public class Accepts {

		@Test
		public void authenticate_shouldAcceptARequestNamingAPermittedServer() {
			configureAllowed(FHIR_BASE);
			present("aud", FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}

		@Test
		public void authenticate_shouldAcceptAnyOfSeveralConfiguredAudiences() {
			configureAllowed(OTHER_FHIR_BASE + " " + FHIR_BASE);
			present("aud", FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}

		@Test
		public void authenticate_shouldAcceptAudiencesSeparatedByLinesOrCommas() {
			configureAllowed(OTHER_FHIR_BASE + ",\n  " + FHIR_BASE + "\n");
			present("aud", FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}

		@CsvSource({
				// a single trailing slash is insignificant, in either position
				"https://ehr.example.org/fhir,  https://ehr.example.org/fhir/",
				"https://ehr.example.org/fhir/, https://ehr.example.org/fhir",
				"https://ehr.example.org/fhir/, https://ehr.example.org/fhir/",
				// surrounding whitespace in the presented value is trimmed
				"https://ehr.example.org/fhir,  '  https://ehr.example.org/fhir  '",
		})
		@ParameterizedTest(name = "configured [{0}] accepts presented [{1}]")
		public void authenticate_shouldIgnoreTrailingSlashesAndWhitespace(String configured, String presented) {
			configureAllowed(configured);
			present("aud", presented);

			validator.authenticate(context);

			assertAccepted();
		}

		@ValueSource(strings = { "resource", "audience" })
		@ParameterizedTest(name = "falls back to the {0} parameter")
		public void authenticate_shouldAcceptTheResourceAndAudienceAliases(String param) {
			configureAllowed(FHIR_BASE);
			present(param, FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}

		@Test
		public void authenticate_shouldPreferAudOverItsAliases() {
			configureAllowed(FHIR_BASE);
			present("aud", FHIR_BASE);
			present("resource", OTHER_FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}

		/**
		 * {@code resource} is a parameter Keycloak recognises, so it is never copied into a prefixed
		 * note: it is stored as a plain client note under its own name. Reading only the prefixed
		 * spelling rejected every client that sent {@code resource} and no {@code aud}.
		 */
		@Test
		public void authenticate_shouldAcceptResourceArrivingAsAPlainClientNote() {
			configureAllowed(FHIR_BASE);
			presentPlain("resource", FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}

		@Test
		public void authenticate_shouldPreferAudOverAPlainResourceNote() {
			configureAllowed(FHIR_BASE);
			present("aud", FHIR_BASE);
			presentPlain("resource", OTHER_FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}

		@ValueSource(strings = { "aud", "resource", "audience" })
		@ParameterizedTest(name = "a plain {0} note is read")
		public void authenticate_shouldReadEveryAudienceParameterFromAPlainNoteToo(String param) {
			configureAllowed(FHIR_BASE);
			presentPlain(param, FHIR_BASE);

			validator.authenticate(context);

			assertAccepted();
		}
	}

	@Nested
	public class Rejects {

		@Test
		public void authenticate_shouldRejectARequestWithNoAudience() {
			configureAllowed(FHIR_BASE);

			validator.authenticate(context);

			assertRejected();
		}

		@ValueSource(strings = { "", "   ", "\t" })
		@ParameterizedTest(name = "blank audience [{0}]")
		public void authenticate_shouldRejectABlankAudience(String presented) {
			configureAllowed(FHIR_BASE);
			present("aud", presented);

			validator.authenticate(context);

			assertRejected();
		}

		@Test
		public void authenticate_shouldRejectAnAudienceNamingAnotherServer() {
			configureAllowed(FHIR_BASE);
			present("aud", OTHER_FHIR_BASE);

			validator.authenticate(context);

			assertRejected();
		}

		/**
		 * The bypasses a prefix or substring comparison would let through. Each of these contains the
		 * permitted audience, so any implementation reaching for startsWith or contains fails here.
		 */
		@ValueSource(strings = {
				// extra path characters appended directly
				FHIR_BASE + "Evil",
				FHIR_BASE + ".evil.example.org",
				// permitted audience as a path segment of a hostile server
				"https://evil.example.org/" + FHIR_BASE,
				// permitted audience smuggled into a query string
				"https://evil.example.org/?a=" + FHIR_BASE,
				// permitted audience in userinfo, so the real host is evil.example.org
				"https://" + FHIR_BASE + "@evil.example.org",
				// permitted audience in a fragment
				"https://evil.example.org/#" + FHIR_BASE,
				// a prefix of the permitted audience, which startsWith in reverse would accept
				"https://openmrs.example.org/openmrs",
				// scheme downgrade
				"http://openmrs.example.org/openmrs/ws/fhir2/R4",
				// more than one trailing slash is not the same resource
				FHIR_BASE + "//",
		})
		@ParameterizedTest(name = "does not accept [{0}]")
		public void authenticate_shouldRejectNearMissesAndSmuggledAudiences(String presented) {
			configureAllowed(FHIR_BASE);
			present("aud", presented);

			validator.authenticate(context);

			assertRejected();
		}

		@Test
		public void authenticate_shouldRejectAnAudienceDifferingOnlyByCase() {
			configureAllowed(FHIR_BASE);
			present("aud", FHIR_BASE.toUpperCase());

			validator.authenticate(context);

			assertRejected();
		}
	}

	@Nested
	public class FailsClosed {

		@Test
		public void authenticate_shouldFailClosedWithNoAuthenticatorConfig() {
			when(context.getAuthenticatorConfig()).thenReturn(null);
			present("aud", FHIR_BASE);

			validator.authenticate(context);

			assertRejected();
		}

		@Test
		public void authenticate_shouldFailClosedWhenTheAudienceKeyIsAbsent() {
			AuthenticatorConfigModel config = new AuthenticatorConfigModel();
			config.setConfig(new HashMap<>());
			when(context.getAuthenticatorConfig()).thenReturn(config);
			present("aud", FHIR_BASE);

			validator.authenticate(context);

			assertRejected();
		}

		@ValueSource(strings = { "", "   ", ",", " , ,, " })
		@ParameterizedTest(name = "configured audiences are effectively empty [{0}]")
		public void authenticate_shouldFailClosedOnBlankConfiguration(String allowed) {
			configureAllowed(allowed);
			present("aud", FHIR_BASE);

			validator.authenticate(context);

			assertRejected();
		}

		/** An unconfigured validator must not treat empty-versus-empty as a match. */
		@Test
		public void authenticate_shouldFailClosedWhenBothConfigAndAudienceAreBlank() {
			configureAllowed("");

			validator.authenticate(context);

			assertRejected();
		}
	}

	@Nested
	public class Plumbing {

		@Test
		public void authenticate_shouldRejectRatherThanCrashWithNoAuthenticationSession() {
			configureAllowed(FHIR_BASE);
			when(context.getAuthenticationSession()).thenReturn(null);

			validator.authenticate(context);

			assertRejected();
		}

		@Test
		public void requiresUser_shouldNotRequireAUserSoItCanRunBeforeLogin() {
			assertEquals(false, validator.requiresUser());
		}

		@Test
		public void action_shouldRevalidateOnActionRatherThanTrustTheSubmission() {
			configureAllowed(FHIR_BASE);
			present("aud", OTHER_FHIR_BASE);

			validator.action(context);

			assertRejected();
		}
	}
}
