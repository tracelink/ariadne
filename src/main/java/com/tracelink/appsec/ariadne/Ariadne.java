/*
Copyright 2019 TraceLink, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.tracelink.appsec.ariadne;

import com.tracelink.appsec.ariadne.analyze.Analyzer;
import com.tracelink.appsec.ariadne.cli.AriadneCLI;
import com.tracelink.appsec.ariadne.read.dependency.DependencyReader;
import com.tracelink.appsec.ariadne.read.vulnerability.VulnerabilityReader;
import com.tracelink.appsec.ariadne.write.Writer;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Ariadne {

	private static final Logger LOG = LoggerFactory.getLogger(Ariadne.class);

	public static void main(String[] args) {
		AriadneCLI cli = new AriadneCLI();
		boolean success = cli.parseArgs(args);
		if (!success) {
			return;
		}

		DependencyReader dependencyReader = cli.getDependencyReader();
		VulnerabilityReader vulnerabilityReader = cli.getVulnerabilityReader();
		Analyzer analyzer = cli.getAnalyzer();
		Writer writer = cli.getWriter();
		boolean writeStats = cli.getWriteStats();

		try {
			LOG.info("Reading dependencies and vulnerabilities");
			List<Map.Entry<String, String>> dependencies = dependencyReader.readDependencies();
			List<Map.Entry<String, Integer>> vulnerabilities = vulnerabilityReader
					.readVulnerabilities();
			LOG.info("Analyzing data");
			analyzer.analyzeDependencies(dependencies);
			analyzer.analyzeVulnerabilities(vulnerabilities);
			analyzer.analyzeTiers();
			writer.setArtifacts(analyzer.getArtifacts());
			if (writeStats) {
				LOG.info("Writing stats");
				writer.writeDependencies();
				writer.writeVulnerabilities();
			}
			LOG.info("Writing tiers");
			writer.writeTiers();
		} catch (Exception e) {
			LOG.error("Exception occurred during analysis", e);
		}
	}
}
