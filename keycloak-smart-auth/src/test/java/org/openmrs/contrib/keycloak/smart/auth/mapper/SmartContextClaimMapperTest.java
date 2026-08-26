/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * An omission here is not a crash but an app that launches with no patient, so these assert both the
 * claims that must appear and that nothing appears when there is no context.
 */
@ExtendWith(MockitoExtension.class)
public class SmartContextClaimMapperTest {

	private static final String PATIENT_UUID = "6a1b2c3d-0000-4444-8888-abcdefabcdef";

	private static final String VISIT_UUID = "9f8e7d6c-1111-4222-9333-fedcbafedcba";

	@Mock
	private UserSessionModel userSession;

	@Mock
	private KeycloakSession keycloakSession;

	@Mock
	private ClientSessionContext clientSessionContext;

	private SmartContextClaimMapper mapper;

	private AccessTokenResponse response;

	private Map<String, String> notes;

	@BeforeEach
	public void setUp() {
		mapper = new SmartContextClaimMapper();
		response = new AccessTokenResponse();
		notes = new HashMap<>();
		lenient().when(userSession.getNote(anyString())).thenAnswer(inv -> notes.get(inv.getArgument(0)));
	}

	/** A mapper model configured the way the realm import configures it. */
	private ProtocolMapperModel mapperModel(String sessionNote, String claimName) {
		ProtocolMapperModel model = new ProtocolMapperModel();
		model.setProtocolMapper(SmartContextClaimMapper.PROVIDER_ID);
		Map<String, String> config = new HashMap<>();
		if (sessionNote != null) {
			config.put(ProtocolMapperUtils.USER_SESSION_NOTE, sessionNote);
		}
		if (claimName != null) {
			config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, claimName);
		}
		config.put(OIDCAttributeMapperHelper.JSON_TYPE, "String");
		config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN_RESPONSE, "true");
		model.setConfig(config);
		return model;
	}

	private AccessTokenResponse transform(ProtocolMapperModel model) {
		return mapper.transformAccessTokenResponse(response, model, keycloakSession, userSession, clientSessionContext);
	}

	@Test
	public void transformAccessTokenResponse_shouldSendASelectedPatientAsThePatientClaim() {
		notes.put(SmartContextClaimMapper.SMART_PATIENT_PARAMS, PATIENT_UUID);

		AccessTokenResponse result = transform(mapperModel(SmartContextClaimMapper.SMART_PATIENT_PARAMS, "patient"));

		assertEquals(PATIENT_UUID, result.getOtherClaims().get("patient"));
	}

	/**
	 * OpenMRS records the context as a visit; SMART calls it an encounter. The rename is the mapper's
	 * job and is easy to lose in a refactor.
	 */
	@Test
	public void transformAccessTokenResponse_shouldSendASelectedVisitAsTheEncounterClaim() {
		notes.put(SmartContextClaimMapper.SMART_VISIT_PARAMS, VISIT_UUID);

		AccessTokenResponse result = transform(mapperModel(SmartContextClaimMapper.SMART_VISIT_PARAMS, "encounter"));

		assertEquals(VISIT_UUID, result.getOtherClaims().get("encounter"));
		assertFalse(result.getOtherClaims().containsKey("visit"),
				"SMART clients look for 'encounter'; a 'visit' claim would be OpenMRS jargon leaking out");
	}

	@Test
	public void transformAccessTokenResponse_shouldReportBothContextsWhenBothWereSelected() {
		notes.put(SmartContextClaimMapper.SMART_PATIENT_PARAMS, PATIENT_UUID);
		notes.put(SmartContextClaimMapper.SMART_VISIT_PARAMS, VISIT_UUID);

		AccessTokenResponse result = transform(mapperModel(SmartContextClaimMapper.SMART_PATIENT_PARAMS, "patient"));

		assertEquals(PATIENT_UUID, result.getOtherClaims().get("patient"));
		assertEquals(VISIT_UUID, result.getOtherClaims().get("encounter"));
	}

	@Test
	public void transformAccessTokenResponse_shouldOmitContextClaimsWhenNothingWasSelected() {
		AccessTokenResponse result = transform(mapperModel(SmartContextClaimMapper.SMART_PATIENT_PARAMS, "patient"));

		assertFalse(result.getOtherClaims().containsKey("patient"));
		assertFalse(result.getOtherClaims().containsKey("encounter"));
		assertTrue(result.getOtherClaims().isEmpty(), "an unlaunched token should carry no SMART context at all");
	}

	/**
	 * Keycloak 26 removed splitClaimPath, so mapClaim replaced it; this pins that dotted claim names
	 * still nest.
	 */
	@Test
	public void transformAccessTokenResponse_shouldNestADottedClaimName() {
		notes.put(SmartContextClaimMapper.SMART_PATIENT_PARAMS, PATIENT_UUID);

		AccessTokenResponse result = transform(mapperModel(SmartContextClaimMapper.SMART_PATIENT_PARAMS, "smart.context.patient"));

		Object smart = result.getOtherClaims().get("smart");
		Map<?, ?> smartMap = assertInstanceOf(Map.class, smart, "the first path segment should hold a nested object");
		Map<?, ?> contextMap = assertInstanceOf(Map.class, smartMap.get("context"),
				"the second path segment should hold a nested object");
		assertEquals(PATIENT_UUID, contextMap.get("patient"));
	}

	@Test
	public void transformAccessTokenResponse_shouldWriteNothingWhenNoClaimNameIsConfigured() {
		notes.put(SmartContextClaimMapper.SMART_PATIENT_PARAMS, PATIENT_UUID);

		AccessTokenResponse result = transform(mapperModel(SmartContextClaimMapper.SMART_PATIENT_PARAMS, null));

		// transformAccessTokenResponse still sets patient; the generic path must add nothing.
		assertEquals(PATIENT_UUID, result.getOtherClaims().get("patient"));
		assertEquals(1, result.getOtherClaims().size(), "no additional claim should be invented without a claim name");
	}

	@Test
	public void transformAccessTokenResponse_shouldWriteNothingWhenTheSessionNoteIsEmpty() {
		AccessTokenResponse result = transform(mapperModel("smart-oidc-note.nothing-here", "whatever"));

		assertFalse(result.getOtherClaims().containsKey("whatever"));
	}

	/**
	 * The access token and the id token are separate destinations from the token response, each gated
	 * by its own config flag. A resource server sees only the access token.
	 */
	private ProtocolMapperModel tokenModel(String sessionNote, String claimName, boolean accessToken,
			boolean idToken) {
		ProtocolMapperModel model = mapperModel(sessionNote, claimName);
		model.getConfig().put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, String.valueOf(accessToken));
		model.getConfig().put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, String.valueOf(idToken));
		return model;
	}

	/** transformAccessToken consults the client for the lightweight-token setting before mapping. */
	private void stubLightweightTokenLookup() {
		KeycloakContext keycloakContext = org.mockito.Mockito.mock(KeycloakContext.class);
		ClientModel client = org.mockito.Mockito.mock(ClientModel.class);
		lenient().when(keycloakSession.getContext()).thenReturn(keycloakContext);
		lenient().when(keycloakContext.getClient()).thenReturn(client);
		lenient().when(client.getAttribute(anyString())).thenReturn(null);
	}

	@Test
	public void transformAccessToken_shouldPutTheLaunchContextInTheAccessToken() {
		stubLightweightTokenLookup();
		notes.put(SmartContextClaimMapper.SMART_PATIENT_PARAMS, PATIENT_UUID);

		AccessToken token = (AccessToken) mapper.transformAccessToken(new AccessToken(),
				tokenModel(SmartContextClaimMapper.SMART_PATIENT_PARAMS, "patient", true, false), keycloakSession,
				userSession, clientSessionContext);

		assertEquals(PATIENT_UUID, token.getOtherClaims().get("patient"),
				"a resource server sees only the access token, so the context has to be in it");
	}

	@Test
	public void transformAccessToken_shouldWriteNothingWhenTheLaunchEstablishedNoContext() {
		stubLightweightTokenLookup();
		notes.put(SmartContextClaimMapper.SMART_PATIENT_PARAMS, "");

		AccessToken token = (AccessToken) mapper.transformAccessToken(new AccessToken(),
				tokenModel(SmartContextClaimMapper.SMART_PATIENT_PARAMS, "patient", true, false), keycloakSession,
				userSession, clientSessionContext);

		assertFalse(token.getOtherClaims().containsKey("patient"),
				"an empty reference is worse than none; the claim should be absent");
	}

	@Test
	public void transformIDToken_shouldPutFhirUserInTheIdToken() {
		notes.put(SmartContextClaimMapper.SMART_FHIR_USER_PARAMS, "Practitioner/" + PATIENT_UUID);

		IDToken token = mapper.transformIDToken(new IDToken(),
				tokenModel(SmartContextClaimMapper.SMART_FHIR_USER_PARAMS, "fhirUser", false, true), keycloakSession,
				userSession, clientSessionContext);

		assertEquals("Practitioner/" + PATIENT_UUID, token.getOtherClaims().get("fhirUser"),
				"SMART puts fhirUser in the id_token");
	}

	@Test
	public void transformIDToken_shouldWriteNothingWhenTheLaunchEstablishedNoContext() {
		notes.put(SmartContextClaimMapper.SMART_FHIR_USER_PARAMS, "");

		IDToken token = mapper.transformIDToken(new IDToken(),
				tokenModel(SmartContextClaimMapper.SMART_FHIR_USER_PARAMS, "fhirUser", false, true), keycloakSession,
				userSession, clientSessionContext);

		assertFalse(token.getOtherClaims().containsKey("fhirUser"));
	}

	/**
	 * TokenManager filters mappers by {@code instanceof} before calling any of them, so dropping one of
	 * these interfaces silently empties that destination -- the transform method stays inherited from
	 * AbstractOIDCProtocolMapper and keeps working when called directly, so only the type catches it.
	 * These are the destinations SMART reads launch context from; TokenManager dispatches on further
	 * mapper interfaces, which this mapper does not implement.
	 */
	@Test
	public void mapper_shouldDeclareTheInterfacesForTheTokenResponseAccessTokenAndIdToken() {
		assertInstanceOf(OIDCAccessTokenResponseMapper.class, mapper,
				"without this the token response carries no patient or encounter");
		assertInstanceOf(OIDCAccessTokenMapper.class, mapper, "without this the access token carries no context");
		assertInstanceOf(OIDCIDTokenMapper.class, mapper, "without this the id token carries no fhirUser");
	}

	@Test
	public void getId_shouldRegisterForTheAccessTokenResponse() {
		assertEquals("smart-context-claim-mapper", mapper.getId(),
				"the provider id appears in realm configuration; changing it silently breaks every realm");
		assertEquals("smart-oidc-note.patient", SmartContextClaimMapper.SMART_PATIENT_PARAMS);
		assertEquals("smart-oidc-note.visit", SmartContextClaimMapper.SMART_VISIT_PARAMS);
	}
}
