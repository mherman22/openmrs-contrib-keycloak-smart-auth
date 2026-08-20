/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth.token;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SmartUserNameTokenTest {
	
	private static String audienceOf(String url) throws MalformedURLException {
		return SmartUserNameToken.audienceFor(new URL(url));
	}
	
	@Test
	@DisplayName("an address written without a port keeps its default, rather than becoming :-1")
	void omitsAnUnstatedPort() throws Exception {
		// URL.getPort() answers -1 here, and -1 != 80, so the obvious comparison against getDefaultPort()
		// appended it. Tokens went out with an audience of http://localhost:-1, which nothing can match.
		assertEquals("http://localhost", audienceOf("http://localhost/openmrs/ms/smartPatientSelection"));
		assertEquals("https://ehr.example.org", audienceOf("https://ehr.example.org/openmrs/ms/smartPatientSelection"));
	}
	
	@Test
	@DisplayName("a port equal to the scheme's default is left out")
	void omitsARedundantPort() throws Exception {
		assertEquals("http://localhost", audienceOf("http://localhost:80/openmrs"));
		assertEquals("https://ehr.example.org", audienceOf("https://ehr.example.org:443/openmrs"));
	}
	
	@Test
	@DisplayName("a port that is not the default is kept")
	void keepsAnExplicitPort() throws Exception {
		assertEquals("http://localhost:8080", audienceOf("http://localhost:8080/openmrs/ms/smartPatientSelection"));
		assertEquals("https://ehr.example.org:8443", audienceOf("https://ehr.example.org:8443/openmrs"));
	}
	
	@Test
	@DisplayName("the audience is an origin, carrying no path, query or fragment")
	void carriesOriginOnly() throws Exception {
		assertEquals("http://localhost:8180",
		    audienceOf("http://localhost:8180/realms/openmrs/login-actions/authenticate?session_code=abc#x"));
	}
}
