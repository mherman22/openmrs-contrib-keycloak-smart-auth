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

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.UserSessionNoteMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

/**
 * Puts SMART launch context where a client can read it. All three token mappers are implemented: apps
 * read the response, resource servers see only the access token, {@code fhirUser} goes in the id_token.
 */
public class SmartContextClaimMapper extends AbstractOIDCProtocolMapper
		implements OIDCAccessTokenResponseMapper, OIDCAccessTokenMapper, OIDCIDTokenMapper {

	public static final String PROVIDER_ID = "smart-context-claim-mapper";

	public static final String SMART_PATIENT_PARAMS = "smart-oidc-note.patient";

	public static final String SMART_VISIT_PARAMS = "smart-oidc-note.visit";

	public static final String SMART_FHIR_USER_PARAMS = "smart-oidc-note.fhirUser";

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

	static {
		ProviderConfigProperty property;
		property = new ProviderConfigProperty();
		property.setName(ProtocolMapperUtils.USER_SESSION_NOTE);
		property.setLabel(ProtocolMapperUtils.USER_SESSION_MODEL_NOTE_LABEL);
		property.setHelpText(ProtocolMapperUtils.USER_SESSION_MODEL_NOTE_HELP_TEXT);
		property.setType(ProviderConfigProperty.STRING_TYPE);
		CONFIG_PROPERTIES.add(property);
		OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, UserSessionNoteMapper.class);
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayCategory() {
		return "Token response mapper";
	}

	@Override
	public String getDisplayType() {
		return "SMART Context Claim";
	}

	@Override
	public String getHelpText() {
		return "Maps a user session note to a SMART context claim";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

	@Override
	public AccessTokenResponse transformAccessTokenResponse(AccessTokenResponse token, ProtocolMapperModel mappingModel,
			KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

		// Add custom claim to AccessTokenResponse
		String patientUuid = userSession.getNote(SMART_PATIENT_PARAMS);
		String visitUuid = userSession.getNote(SMART_VISIT_PARAMS);

		// Blank means the launch established no such context; an empty reference is worse than none.
		if (!isBlank(patientUuid)) {
			token.getOtherClaims().put("patient", patientUuid);
		}
		if (!isBlank(visitUuid)) {
			token.getOtherClaims().put("encounter", visitUuid);
		}

		// setClaim does not know that blank means absent, so it is skipped when the note is empty.
		String configuredNote = mappingModel.getConfig().get(ProtocolMapperUtils.USER_SESSION_NOTE);

		if (configuredNote == null || !isBlank(userSession.getNote(configuredNote))) {
			setClaim(token, mappingModel, userSession, session, clientSessionCtx);
		}

		return token;
	}

	private static boolean isBlank(String value) {
		return value == null || value.trim().isEmpty();
	}

	/**
	 * The access-token and id-token path; the realm's {@code access.token.claim} and
	 * {@code id.token.claim} decide which one an instance writes to. Blank is treated as absent.
	 */
	@Override
	protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
			KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		String noteName = mappingModel.getConfig().get(ProtocolMapperUtils.USER_SESSION_NOTE);

		if (noteName == null || isBlank(userSession.getNote(noteName))) {
			return;
		}

		OIDCAttributeMapperHelper.mapClaim(token, mappingModel, userSession.getNote(noteName));
	}

	@Override
	protected void setClaim(AccessTokenResponse token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
			KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
		String noteName = mappingModel.getConfig().get(ProtocolMapperUtils.USER_SESSION_NOTE);
		String noteValue = userSession.getNote(noteName);
		if (noteValue == null) {
			return;
		}

		Object attributeValue = OIDCAttributeMapperHelper.mapAttributeValue(mappingModel, noteValue);

		if (attributeValue == null) {
			return;
		}

		if (mappingModel.getConfig().get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME) == null) {
			return;
		}

		// Keycloak splits the dotted claim path and builds the nested maps itself.
		OIDCAttributeMapperHelper.mapClaim(token, mappingModel, attributeValue);
	}
}
