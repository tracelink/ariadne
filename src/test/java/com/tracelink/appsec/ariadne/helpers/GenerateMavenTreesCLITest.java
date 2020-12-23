package com.tracelink.appsec.ariadne.helpers;

import com.tracelink.appsec.ariadne.mock.LoggerRule;
import java.io.File;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

public class GenerateMavenTreesCLITest {

	private static final String RESOURCES = "src/test/resources/";

	@Rule
	public LoggerRule loggerRule = LoggerRule.forClass(GenerateMavenTreesCLI.class);

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
	public void testGenerateMavenTreesCLI() {
		GenerateMavenTreesCLI cli = new GenerateMavenTreesCLI();
		cli.parseArgs(new String[]{
				"-p", RESOURCES + "helpers",
				"-o", RESOURCES + "output",
				"-r", "4",
				"-d", "-Dfoo=bar",
				"-s", "special,-Dfoo=baz", "special2"
		});
		Assert.assertEquals(new File(RESOURCES + "helpers"), cli.getProjectsDir());
		Assert.assertEquals(new File(RESOURCES + "output"), cli.getOutputDir());
		Assert.assertEquals(4, cli.getMaxDepth());
		Assert.assertEquals("-Dfoo=bar", cli.getDefaultOption());
		Assert.assertEquals(2, cli.getSpecialOptions().size());
	}

	@Test
	public void testGenerateMavenTreesCLIMissingOption() {
		GenerateMavenTreesCLI cli = new GenerateMavenTreesCLI();
		cli.parseArgs(new String[]{
				"-p", RESOURCES + "helpers",
				"-r", "4",
				"-d", "-Dfoo=bar",
				"-s", "special,-Dfoo=baz", "special2"
		});

		Assert.assertTrue(loggerRule.getMessages().get(0)
				.contains(
						"Exception occurred while parsing arguments: Missing required option: o"));
	}

	@Test
	public void testGenerateMavenTreesCLIBadProjectsFolder() {
		GenerateMavenTreesCLI cli = new GenerateMavenTreesCLI();
		cli.parseArgs(new String[]{
				"-p", RESOURCES + "foo",
				"-o", RESOURCES + "output",
				"-r", "4",
				"-d", "-Dfoo=bar",
				"-s", "special,-Dfoo=baz", "special2"
		});

		Assert.assertTrue(loggerRule.getMessages().get(0)
				.contains(
						"Exception occurred while parsing arguments: Please provide a valid path to the projects directory"));
	}

	@Test
	public void testGenerateMavenTreesCLIBadOutputFolder() {
		GenerateMavenTreesCLI cli = new GenerateMavenTreesCLI();
		cli.parseArgs(new String[]{
				"-p", RESOURCES + "helpers",
				"-o", RESOURCES + "helpers/random-file.txt",
				"-r", "4",
				"-d", "-Dfoo=bar",
				"-s", "special,-Dfoo=baz", "special2"
		});

		Assert.assertTrue(loggerRule.getMessages().get(0)
				.contains(
						"Exception occurred while parsing arguments: Please provide a valid path to the output directory"));
	}
}

