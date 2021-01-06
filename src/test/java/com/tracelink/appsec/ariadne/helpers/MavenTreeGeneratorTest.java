package com.tracelink.appsec.ariadne.helpers;

import com.tracelink.appsec.ariadne.mock.LoggerRule;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

public class MavenTreeGeneratorTest {

	private static final String RESOURCES = "src/test/resources/";

	@Rule
	public LoggerRule loggerRule = LoggerRule.forClass(MavenTreeGenerator.class);

	@Before
	public void setup() {
		File output = new File(RESOURCES + "output");
		output.mkdirs();
	}

	@After
	public void clean() {
		File output = new File(RESOURCES + "output");
		File[] files = output.listFiles();
		if (files != null) {
			for (File file : files) {
				file.delete();
			}
		}
		output.delete();
	}

	@Test
	public void testBuildTrees() throws Exception {
		MavenTreeGenerator mtg = new MavenTreeGenerator(new File(RESOURCES + "output"), 2, "",
				Collections.singletonMap("simple-project", "-Dsimple=special"));

		mtg.buildTrees(new File(RESOURCES + "helpers"), 0);

		try (BufferedReader reader = new BufferedReader(
				new FileReader(RESOURCES + "output/simple-project.txt"))) {
			List<String> lines = reader.lines().collect(Collectors.toList());
			Assert.assertTrue(
					lines.stream()
							.anyMatch(line -> line
									.contains("com.example:special-project:jar:1.0.0")));
		}

		try (BufferedReader reader = new BufferedReader(
				new FileReader(RESOURCES + "output/parent-project.txt"))) {
			List<String> lines = reader.lines().collect(Collectors.toList());
			Assert.assertTrue(
					lines.stream()
							.anyMatch(
									line -> line.contains("com.example:parent-project:pom:1.0.0")));
			Assert.assertTrue(
					lines.stream()
							.anyMatch(line -> line.contains("com.example:module-1:jar:1.0.0")));
		}

		try (BufferedReader reader = new BufferedReader(
				new FileReader(RESOURCES + "output/nested-project.txt"))) {
			List<String> lines = reader.lines().collect(Collectors.toList());
			Assert.assertTrue(
					lines.stream()
							.anyMatch(
									line -> line.contains("com.example:nested-project:jar:1.0.0")));
		}
	}

	@Test
	public void testBuildTreesExceedMaxDepth() throws Exception {
		MavenTreeGenerator mtg = new MavenTreeGenerator(new File(RESOURCES + "output"), 1, "",
				Collections.singletonMap("simple-project", "-Dsimple=special"));
		mtg.buildTrees(new File(RESOURCES + "helpers"), 0);

		Assert.assertTrue(new File(RESOURCES + "output/simple-project.txt").exists());
		Assert.assertTrue(new File(RESOURCES + "output/parent-project.txt").exists());
		Assert.assertFalse(new File(RESOURCES + "output/nested-project.txt").exists());
	}

	@Test
	public void testBuildTreesFailSimple() throws Exception {
		MavenTreeGenerator mtg = new MavenTreeGenerator(new File(RESOURCES + "output"), 1, "",
				Collections.emptyMap());
		mtg.buildTrees(new File(RESOURCES + "helpers"), 0);

		Assert.assertFalse(new File(RESOURCES + "output/simple-project.txt").exists());
		Assert.assertTrue(new File(RESOURCES + "output/parent-project.txt").exists());
		Assert.assertFalse(new File(RESOURCES + "output/nested-project.txt").exists());
	}

	@Test
	public void testBuildTreesException() throws Exception {
		String defaultOption = Character.toString('\u0000');
		MavenTreeGenerator mtg = new MavenTreeGenerator(new File(RESOURCES + "output"), 1,
				defaultOption,
				Collections.singletonMap("simple-project", "-Dsimple=special"));
		mtg.buildTrees(new File(RESOURCES + "helpers"), 0);

		List<String> messages = loggerRule.getMessages();
		Assert.assertTrue(messages.stream()
				.anyMatch(
						m -> m.contains("Exception occurred: invalid null character in command")));
	}

	@Test
	public void testIdentifyParents() throws Exception {
		MavenTreeGenerator mtg = new MavenTreeGenerator(new File(RESOURCES + "output"), 2, "",
				Collections.singletonMap("simple-project", "-Dsimple=special"));
		mtg.identifyParents(new File(RESOURCES + "helpers"), 0);

		try (BufferedReader reader = new BufferedReader(
				new FileReader(RESOURCES + "output/parents.txt"))) {
			List<String> lines = reader.lines().collect(Collectors.toList());
			Assert.assertEquals(1, lines.stream()
					.filter(line -> line.equals("\\- com.example:parent-project:1.0.0")).count());
			Assert.assertEquals("com.example:module-1:1.0.0", lines.get(0));
		}
	}

	@Test
	public void testIdentifyParentsExceptionProcessBuilder() throws Exception {
		String defaultOption = Character.toString('\u0000');
		MavenTreeGenerator mtg = new MavenTreeGenerator(new File(RESOURCES + "output"), 1,
				defaultOption,
				Collections.singletonMap("simple-project", "-Dsimple=special"));
		mtg.identifyParents(new File(RESOURCES + "helpers"), 0);

		List<String> messages = loggerRule.getMessages();
		Assert.assertTrue(messages.stream()
				.anyMatch(
						m -> m.contains("Exception occurred: invalid null character in command")));
	}

	@Test(expected = RuntimeException.class)
	public void testIdentifyParentsExceptionWriter() throws Exception {
		new File(RESOURCES + "output").delete();
		MavenTreeGenerator mtg = new MavenTreeGenerator(new File(RESOURCES + "output"), 2, "",
				Collections.singletonMap("simple-project", "-Dsimple=special"));

		mtg.identifyParents(new File(RESOURCES + "helpers"), 0);
	}
}
