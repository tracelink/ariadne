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
package com.tracelink.appsec.ariadne.cli;

import com.tracelink.appsec.ariadne.analyze.Analyzer;
import com.tracelink.appsec.ariadne.read.dependency.DependencyReader;
import com.tracelink.appsec.ariadne.read.dependency.DependencyReaderType;
import com.tracelink.appsec.ariadne.read.dependency.MavenDependencyTreeReader;
import com.tracelink.appsec.ariadne.read.dependency.PomExplorerReader;
import com.tracelink.appsec.ariadne.read.vulnerability.NexusIQViolationsReader;
import com.tracelink.appsec.ariadne.read.vulnerability.VeracodeScaIssuesReader;
import com.tracelink.appsec.ariadne.read.vulnerability.VulnerabilityReader;
import com.tracelink.appsec.ariadne.read.vulnerability.VulnerabilityReaderType;
import com.tracelink.appsec.ariadne.write.StandardCsvWriter;
import com.tracelink.appsec.ariadne.write.Writer;
import com.tracelink.appsec.ariadne.write.WriterType;
import java.util.Arrays;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AriadneCLI {

	private static final Logger LOG = LoggerFactory.getLogger(AriadneCLI.class);
	private static final String CMD_LINE_SYNTAX = "java -jar ariadne.jar -d [dependency reader type] [dependency files] -v [vuln reader type] [vuln files] -w [writer type] [output directory] -i [internal ids] [--stats]";
	private final Options options;

	private DependencyReader dependencyReader;
	private VulnerabilityReader vulnerabilityReader;
	private Analyzer analyzer;
	private Writer writer;
	private boolean writeStats;

	public AriadneCLI() {
		Option depOption = Option.builder("d")
				.required()
				.desc("The type of dependency reader to use")
				.longOpt("dep")
				.hasArgs()
				.numberOfArgs(2)
				.build();
		Option vulnOption = Option.builder("v")
				.required()
				.desc("The type of vulnerability reader to use")
				.longOpt("vuln")
				.hasArgs()
				.numberOfArgs(2)
				.build();
		Option writerOption = Option.builder("w")
				.required()
				.desc("The type of writer to use")
				.longOpt("writer")
				.hasArgs()
				.numberOfArgs(2)
				.build();
		Option idOption = Option.builder("i")
				.required()
				.desc("The strings used to identify your internal projects, i.e. 'com.example'")
				.longOpt("ids")
				.hasArgs()
				.build();
		Option statsOption = Option.builder("s")
				.required(false)
				.desc("Indicates that additional stats should be written to the output directory")
				.longOpt("stats")
				.build();

		options = new Options();
		options.addOption(depOption);
		options.addOption(vulnOption);
		options.addOption(writerOption);
		options.addOption(idOption);
		options.addOption(statsOption);
	}

	public boolean parseArgs(String[] args) {
		CommandLineParser parser = new DefaultParser();
		CommandLine commandLine;
		try {
			commandLine = parser.parse(options, args);

			String[] depOptionValues = commandLine.getOptionValues("d");
			String[] vulnOptionValues = commandLine.getOptionValues("v");
			String[] writerOptionValues = commandLine.getOptionValues("w");
			String[] idOptionValues = commandLine.getOptionValues("i");

			// Set dependency reader
			DependencyReaderType dependencyReaderType = DependencyReaderType
					.getTypeForName(depOptionValues[0]);
			switch (dependencyReaderType) {
				case MAVEN_TREE:
					dependencyReader = new MavenDependencyTreeReader(depOptionValues[1]);
					break;
				case POM_EXPLORER:
					dependencyReader = new PomExplorerReader(depOptionValues[1]);
					break;
			}
			// Set vulnerability reader
			VulnerabilityReaderType vulnerabilityReaderType = VulnerabilityReaderType
					.getTypeForName(vulnOptionValues[0]);
			switch (vulnerabilityReaderType) {
				case NEXUS_IQ_VIOLATIONS:
					vulnerabilityReader = new NexusIQViolationsReader(vulnOptionValues[1]);
					break;
				case VERACODE_SCA_ISSUES:
					vulnerabilityReader = new VeracodeScaIssuesReader(vulnOptionValues[1]);
					break;
			}
			// Set analyzer
			analyzer = new Analyzer(Arrays.asList(idOptionValues));
			// Set writer
			WriterType writerType = WriterType.getTypeForName(writerOptionValues[0]);
			switch (writerType) {
				case STANDARD_CSV:
					writer = new StandardCsvWriter(writerOptionValues[1]);
					break;
			}
			// Set stats flag
			writeStats = commandLine.hasOption("s");
		} catch (Exception e) {
			LOG.error("Exception occurred while parsing arguments: {}", e.getMessage());
			new HelpFormatter().printHelp(CMD_LINE_SYNTAX, options);
			return false;
		}
		return true;
	}

	public DependencyReader getDependencyReader() {
		return dependencyReader;
	}

	public VulnerabilityReader getVulnerabilityReader() {
		return vulnerabilityReader;
	}

	public Analyzer getAnalyzer() {
		return analyzer;
	}

	public Writer getWriter() {
		return writer;
	}

	public boolean getWriteStats() {
		return writeStats;
	}
}
