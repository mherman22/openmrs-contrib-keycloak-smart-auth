/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.contrib.keycloak.smart.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.protocol.ProtocolMapper;
import org.openmrs.contrib.keycloak.smart.auth.provider.AlternativeUsernamePasswordFormFactory;

/**
 * Constraints on provider identity that Keycloak enforces at realm-import time rather than at compile
 * time. Each assertion here corresponds to a failure that has actually happened during this port.
 */
public class ProviderContractTest {

	/**
	 * AUTHENTICATION_EXECUTION.AUTHENTICATOR is a VARCHAR(36); a longer id compiles and registers, then
	 * fails realm import.
	 */
	private static final int MAX_AUTHENTICATOR_ID_LENGTH = 36;

	private static final String OUR_PACKAGE = "org.openmrs.contrib.keycloak.smart.auth.";

	/**
	 * Every SPI this plugin registers into. A line naming a class the jar does not contain, or one that
	 * does not implement the SPI whose file it sits in, makes ServiceLoader throw for the whole SPI, so
	 * each file needs checking, not just the authenticators. The interface is carried alongside the file
	 * name because the file name is the only thing that says which SPI a line is claiming to implement.
	 */
	private static final List<Class<?>> REGISTERED_SPIS = Arrays.asList(
			AuthenticatorFactory.class,
			ActionTokenHandlerFactory.class,
			ProtocolMapper.class);

	private static final String SERVICES_FILE = servicesFileFor(AuthenticatorFactory.class);

	private static String servicesFileFor(Class<?> spi) {
		return "META-INF/services/" + spi.getName();
	}

	static List<AuthenticatorFactory> factories() throws Exception {
		List<AuthenticatorFactory> factories = new ArrayList<>();
		for (String className : declaredFactoryClassNames()) {
			factories.add((AuthenticatorFactory) Class.forName(className).getDeclaredConstructor().newInstance());
		}
		return factories;
	}

	private static final Predicate<String> OURS = name -> name.startsWith(OUR_PACKAGE);

	/** Reads the service registration file, so the test covers what Keycloak will actually load. */
	private static List<String> declaredFactoryClassNames() throws IOException {
		return declaredClassNames(SERVICES_FILE, OURS);
	}

	/**
	 * Class names from every copy of {@code servicesFile} on the classpath that {@code selector}
	 * accepts. Keycloak ships its own copy of each of these files, so the selector decides whose
	 * registrations a caller is looking at rather than which copy happens to be found first.
	 */
	private static List<String> declaredClassNames(String servicesFile, Predicate<String> selector)
			throws IOException {
		List<String> names = new ArrayList<>();
		Enumeration<URL> resources = ProviderContractTest.class.getClassLoader().getResources(servicesFile);

		while (resources.hasMoreElements()) {
			URL resource = resources.nextElement();
			try (BufferedReader reader = new BufferedReader(
					new InputStreamReader(resource.openStream(), StandardCharsets.UTF_8))) {
				names.addAll(reader.lines().map(String::trim).filter(l -> !l.isEmpty() && !l.startsWith("#"))
						.filter(selector).collect(Collectors.toList()));
			}
		}

		return names;
	}

	@Test
	public void factories_shouldRegisterEveryAuthenticatorForDiscovery() throws Exception {
		List<String> declared = declaredFactoryClassNames();

		// A factory with no services entry fails silently: it never appears in Keycloak.
		assertTrue(declared.contains(AlternativeUsernamePasswordFormFactory.class.getName()));
		assertTrue(declared.stream().anyMatch(n -> n.endsWith("SmartAudienceValidatorFactory")),
				"the audience validator must be registered or SMART's aud requirement goes unenforced");
		assertTrue(declared.stream().anyMatch(n -> n.endsWith("SmartLaunchAuthenticatorFactory")));
		assertTrue(declared.stream().anyMatch(n -> n.endsWith("SmartLaunchAccessAuthenticatorFactory")));
		assertEquals(4, declared.size(), "unexpected number of registered authenticators; update this test deliberately");

		// The assertions above read the services file, so they cannot see a factory that is in the jar and
		// not in the file. This walks the compiled classes instead, which is the direction that hazard runs.
		List<String> compiled = implementationsOnTheClasspath(AuthenticatorFactory.class);

		assertTrue(compiled.contains(AlternativeUsernamePasswordFormFactory.class.getName()),
				"the classpath scan found no factory it should have, so the loop below is vacuous: " + compiled);

		for (String className : compiled) {
			assertTrue(declared.contains(className), className + " implements AuthenticatorFactory but "
					+ SERVICES_FILE + " does not name it, so Keycloak never loads it");
		}
	}

	/**
	 * This plugin's classes on the classpath that implement {@code spi}, found by walking the compiled
	 * output rather than the registration file, so a class present in the jar and absent from the file is
	 * visible. Classes are loaded without initialising them; only directory classpath entries are walked,
	 * which is what Surefire hands us, and the caller asserts the walk found something. Both compiled
	 * roots are walked, so a test-only AuthenticatorFactory in this package would have to be registered
	 * too -- put one outside this package rather than adding a services entry for it.
	 */
	private static List<String> implementationsOnTheClasspath(Class<?> spi) throws Exception {
		List<String> names = new ArrayList<>();
		ClassLoader loader = ProviderContractTest.class.getClassLoader();
		Enumeration<URL> roots = loader.getResources(OUR_PACKAGE.replace('.', '/'));

		while (roots.hasMoreElements()) {
			URL root = roots.nextElement();

			if (!"file".equals(root.getProtocol())) {
				continue;
			}

			Path packageDir = Paths.get(root.toURI());

			try (Stream<Path> tree = Files.walk(packageDir)) {
				for (Path classFile : tree.filter(f -> f.toString().endsWith(".class")).collect(Collectors.toList())) {
					String relative = packageDir.relativize(classFile).toString();
					String className = OUR_PACKAGE
							+ relative.substring(0, relative.length() - ".class".length()).replace(File.separatorChar,
									'.');
					Class<?> candidate = Class.forName(className, false, loader);

					if (spi.isAssignableFrom(candidate) && !Modifier.isAbstract(candidate.getModifiers())) {
						names.add(className);
					}
				}
			}
		}

		return names;
	}

	@MethodSource("factories")
	@ParameterizedTest(name = "{0}")
	public void getId_shouldFitProviderIdsInTheColumnKeycloakStoresThemIn(AuthenticatorFactory factory) {
		String id = factory.getId();

		assertTrue(id.length() <= MAX_AUTHENTICATOR_ID_LENGTH,
				String.format("provider id '%s' is %d characters; Keycloak's AUTHENTICATOR column holds %d",
						id, id.length(), MAX_AUTHENTICATOR_ID_LENGTH));
	}

	@MethodSource("factories")
	@ParameterizedTest(name = "{0}")
	public void getId_shouldUseProviderIdsThatNeedNoUrlEscaping(AuthenticatorFactory factory) {
		String id = factory.getId();

		assertFalse(id.trim().isEmpty(), "a blank provider id cannot be referenced from a flow");
		assertTrue(id.matches("[a-z0-9-]+"),
				"provider id '" + id + "' should be lowercase kebab-case; it appears in realm JSON and admin URLs");
	}

	@Test
	public void getId_shouldGiveEveryProviderAUniqueId() throws Exception {
		List<String> ids = factories().stream().map(AuthenticatorFactory::getId).collect(Collectors.toList());
		Set<String> unique = new HashSet<>(ids);

		assertEquals(ids.size(), unique.size(), "duplicate provider ids: one silently shadows the other. " + ids);
	}

	/**
	 * Inheriting getId() registered this as auth-username-password-form, replacing the stock login form
	 * for every realm in the instance, and invisibly, since the display name was inherited too.
	 */
	@Test
	public void getId_shouldNotShadowKeycloaksBuiltInLoginForm() {
		AlternativeUsernamePasswordFormFactory ours = new AlternativeUsernamePasswordFormFactory();
		UsernamePasswordFormFactory builtIn = new UsernamePasswordFormFactory();

		assertNotEquals(builtIn.getId(), ours.getId(),
				"sharing the built-in id replaces the stock login form instance-wide");
		assertNotEquals(builtIn.getDisplayType(), ours.getDisplayType(),
				"an identical display name makes the two indistinguishable in the admin console");
	}

	/**
	 * The login form is the one we collided with, but the hazard is not specific to it: factories are
	 * keyed by getId() and the last one loaded wins, so any id shared with a stock authenticator
	 * replaces that authenticator for every realm in the instance.
	 */
	@Test
	public void getId_shouldNotShadowAnyBuiltInKeycloakAuthenticator() throws Exception {
		Set<String> builtInIds = builtInAuthenticatorIds();

		// Without this the loop below would pass by finding nothing to compare against.
		assertFalse(builtInIds.isEmpty(), "no built-in authenticator ids were read, so the check is vacuous");
		assertTrue(builtInIds.contains(new UsernamePasswordFormFactory().getId()),
				"the built-in login form should be among the ids read; " + builtInIds.size() + " were found");

		for (AuthenticatorFactory ours : factories()) {
			assertFalse(builtInIds.contains(ours.getId()),
					"provider id '" + ours.getId() + "' is a stock Keycloak authenticator id; registering it "
							+ "replaces that authenticator for every realm in the instance");
		}
	}

	/** The ids Keycloak's own AuthenticatorFactory registrations claim, read the way Keycloak reads them. */
	private static Set<String> builtInAuthenticatorIds() throws Exception {
		Set<String> ids = new HashSet<>();

		for (String className : declaredClassNames(SERVICES_FILE, OURS.negate())) {
			AuthenticatorFactory factory = (AuthenticatorFactory) Class.forName(className).getDeclaredConstructor()
					.newInstance();
			ids.add(factory.getId());
		}

		return ids;
	}

	/**
	 * A services line naming a class the jar does not contain, or one that does not implement the SPI its
	 * file is named for, makes ServiceLoader throw ServiceConfigurationError for that whole SPI, taking
	 * every sibling registered in the same file down with it -- at Keycloak startup, with nothing to see
	 * at build time. Deleting a line is caught by the emptiness check; replacing a line with a class of
	 * the wrong type is caught by the assertInstanceOf, which is the copy-pasted-filename case.
	 */
	@Test
	public void services_shouldNameOnlyClassesThatCanBeLoaded() throws Exception {
		for (Class<?> spi : REGISTERED_SPIS) {
			String servicesFile = servicesFileFor(spi);
			List<String> declared = declaredClassNames(servicesFile, OURS);

			assertFalse(declared.isEmpty(), servicesFile + " registers none of this plugin's providers");

			for (String className : declared) {
				Object instance = assertDoesNotThrow(
						() -> Class.forName(className).getDeclaredConstructor().newInstance(),
						servicesFile + " names " + className + ", which ServiceLoader would fail to instantiate");

				assertInstanceOf(spi, instance, servicesFile + " names " + className + ", which does not implement "
						+ spi.getName() + "; ServiceLoader rejects the whole file with \"not a subtype\"");
			}
		}
	}

	/**
	 * The subclass exists only to widen the requirement choices. If a future Keycloak offers
	 * ALTERNATIVE on the built-in, this fails and the subclass can be deleted.
	 */
	@Test
	public void getRequirementChoices_shouldStillNeedTheAlternativeLoginForm() {
		Set<AuthenticationExecutionModel.Requirement> builtIn = new HashSet<>(
				Arrays.asList(new UsernamePasswordFormFactory().getRequirementChoices()));
		Set<AuthenticationExecutionModel.Requirement> ours = new HashSet<>(
				Arrays.asList(new AlternativeUsernamePasswordFormFactory().getRequirementChoices()));

		assertFalse(builtIn.contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE),
				"Keycloak's built-in form now offers ALTERNATIVE; AlternativeUsernamePasswordFormFactory is redundant "
						+ "and should be removed along with its realm reference");
		assertTrue(ours.contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE));
	}

	/**
	 * An audience check that another alternative execution can satisfy on its behalf is not a check.
	 */
	@Test
	public void getRequirementChoices_shouldRefuseToRunTheAudienceValidatorAsAlternative() throws Exception {
		AuthenticatorFactory validator = factories().stream()
				.filter(f -> f.getId().equals("smart-audience-validator")).findFirst()
				.orElseThrow(() -> new AssertionError("audience validator not registered"));

		Set<AuthenticationExecutionModel.Requirement> choices = new HashSet<>(
				Arrays.asList(validator.getRequirementChoices()));

		assertFalse(choices.contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE),
				"ALTERNATIVE would let a sibling execution satisfy the flow without validating aud");
		assertTrue(choices.contains(AuthenticationExecutionModel.Requirement.REQUIRED));
	}

	@MethodSource("factories")
	@ParameterizedTest(name = "{0}")
	public void getConfigProperties_shouldDescribeConfigurationWithoutFailing(AuthenticatorFactory factory) {
		assertDoesNotThrow(factory::getConfigProperties,
				"the admin console calls this to render the configuration form");
		assertDoesNotThrow(factory::getDisplayType);
		assertDoesNotThrow(factory::getHelpText);

		if (factory.isConfigurable()) {
			assertFalse(factory.getConfigProperties().isEmpty(),
					factory.getId() + " claims to be configurable but exposes no properties");
		}
	}
}
