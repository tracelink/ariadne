package com.tracelink.appsec.ariadne.helpers;

import com.tracelink.appsec.ariadne.mock.LoggerRule;
import java.io.File;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

public class GenerateMavenTreesTest {

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
	public void testGenerateMavenTrees() {
		GenerateMavenTrees.main(new String[]{
				"-p", RESOURCES + "helpers",
				"-o", RESOURCES + "output",
				"-r", "1",
				"-s", "simple-project,-Dsimple=special"
		});

		Assert.assertTrue(new File(RESOURCES + "output/simple-project.txt").exists());
		Assert.assertTrue(new File(RESOURCES + "output/parent-project.txt").exists());
		Assert.assertFalse(new File(RESOURCES + "output/nested-project.txt").exists());
	}

	@Test
	public void testGenerateMavenTreesTestBadArgs() {
		GenerateMavenTrees.main(new String[]{
				"-p", RESOURCES + "helpers",
				"-r", "1",
				"-s", "simple-project,-Dsimple=special"
		});

		Assert.assertTrue(loggerRule.getMessages().get(0)
				.contains(
						"Exception occurred while parsing arguments: Missing required option: o"));
	}

}
