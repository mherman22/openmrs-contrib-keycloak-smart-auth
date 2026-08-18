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
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.UserSessionNoteMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;

import java.util.ArrayList;
import java.util.List;

public class SmartContextClaimMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenResponseMapper {

	public static final String PROVIDER_ID = "smart-context-claim-mapper";

	public static final String SMART_PATIENT_PARAMS = "smart-oidc-note.patient";

	public static final String SMART_VISIT_PARAMS = "smart-oidc-note.visit";

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

		// Blank means the launch established no such context, which is how the authenticator clears a
		// note left by an earlier launch on the same session. Emitting it would hand the app an empty
		// context reference, which is worse than none: a client cannot tell it apart from a real id.
		if (!isBlank(patientUuid)) {
			token.getOtherClaims().put("patient", patientUuid);
		}
		if (!isBlank(visitUuid)) {
			token.getOtherClaims().put("encounter", visitUuid);
		}

		// setClaim writes the configured note under the configured claim name, which is the same context
		// by another route -- and it does not know that blank means absent, so on its own it emitted
		// "encounter": "" once a launch had cleared the note. Skipped when the note this instance is
		// configured to read holds nothing.
		String configuredNote = mappingModel.getConfig().get(ProtocolMapperUtils.USER_SESSION_NOTE);

		if (configuredNote == null || !isBlank(userSession.getNote(configuredNote))) {
			setClaim(token, mappingModel, userSession, session, clientSessionCtx);
		}

		return token;
	}

	private static boolean isBlank(String value) {
		return value == null || value.trim().isEmpty();
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

		// Keycloak handles splitting the dotted claim path and building the nested
		// maps itself; splitClaimPath was removed in favour of mapClaim.
		OIDCAttributeMapperHelper.mapClaim(token, mappingModel, attributeValue);
	}
}
