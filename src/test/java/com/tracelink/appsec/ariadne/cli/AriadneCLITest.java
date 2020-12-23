package com.tracelink.appsec.ariadne.cli;

import com.tracelink.appsec.ariadne.mock.LoggerRule;
import com.tracelink.appsec.ariadne.read.dependency.PomExplorerReader;
import com.tracelink.appsec.ariadne.read.vulnerability.NexusIQViolationsReader;
import com.tracelink.appsec.ariadne.write.StandardCsvWriter;
import java.io.File;
import org.junit.After;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

public class AriadneCLITest {

	private static final String RESOURCES = "src/test/resources/";

	@Rule
	public LoggerRule loggerRule = LoggerRule.forClass(AriadneCLI.class);

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
	public void testParseArgsPomExplorer() {
		AriadneCLI cli = new AriadneCLI();
		cli.parseArgs(new String[]{
				"-d", "pom-explorer", RESOURCES + "dependency/pom-explorer.csv",
				"-v", "nexus-iq-vios", RESOURCES + "vulnerability/violations.csv",
				"-w", "csv", RESOURCES + "output/",
				"-i", "com.example"
		});

		Assert.assertTrue(cli.getDependencyReader() instanceof PomExplorerReader);
		Assert.assertTrue(cli.getVulnerabilityReader() instanceof NexusIQViolationsReader);
		Assert.assertTrue(cli.getWriter() instanceof StandardCsvWriter);
		Assert.assertFalse(cli.getWriteStats());
	}

	@Test()
	public void testParseArgsBadType() {
		AriadneCLI cli = new AriadneCLI();
		cli.parseArgs(new String[]{
				"-d", "pom-explorer", RESOURCES + "dependency/pom-explorer.csv",
				"-v", "nexus-iq-vios", RESOURCES + "vulnerability/violations.csv",
				"-w", "foo", RESOURCES + "output/",
				"-i", "com.example"
		});

		Assert.assertEquals("Exception occurred while parsing arguments: Unknown writer type - foo",
				loggerRule.getMessages().get(0));
	}
}
