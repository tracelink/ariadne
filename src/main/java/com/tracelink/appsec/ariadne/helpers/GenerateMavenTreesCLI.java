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
package com.tracelink.appsec.ariadne.helpers;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Command line interface for Maven dependency tree generation. Reads arguments from the command
 * line and parses them into usable parameters that can be passed to the {@link GenerateMavenTrees}
 * class.
 *
 * @author mcool
 */
public class GenerateMavenTreesCLI {

	private static final Logger LOG = LoggerFactory.getLogger(GenerateMavenTreesCLI.class);
	private static final String CMD_LINE_SYNTAX = "maventrees -p [Maven projects directory] -o [output directory] -r [max recursion depth] -d [default option] -s [special options]";
	private final Options options;

	private File projectsDir;
	private File outputDir;
	private int maxDepth = 4;
	private String defaultOption = "";
	private Map<String, String> specialOptions;

	public GenerateMavenTreesCLI() {
		Option projectsOption = Option.builder("p")
				.required()
				.desc("Path to the directory containing all Maven projects")
				.longOpt("proj")
				.hasArgs()
				.numberOfArgs(1)
				.build();
		Option outputOption = Option.builder("o")
				.required()
				.desc("Path to the output directory")
				.longOpt("out")
				.hasArgs()
				.numberOfArgs(1)
				.build();
		Option recursionOption = Option.builder("r")
				.required(false)
				.desc("Max depth of recursion")
				.longOpt("recursion")
				.hasArgs()
				.numberOfArgs(1)
				.build();
		Option defaultOption = Option.builder("d")
				.required(false)
				.desc("The default option string to be used when building dependency trees, i.e. '-Dversion=foo")
				.longOpt("default")
				.hasArg()
				.numberOfArgs(1)
				.build();
		Option specialOption = Option.builder("s")
				.required(false)
				.desc("Special option strings to be used when building dependency trees, i.e. 'com.example.api,-Dversion=bar'")
				.longOpt("special")
				.hasArgs()
				.build();

		options = new Options();
		options.addOption(projectsOption);
		options.addOption(outputOption);
		options.addOption(recursionOption);
		options.addOption(defaultOption);
		options.addOption(specialOption);
	}

	/**
	 * Parses arguments from the command line. If arguments are invalid, logs an error along with
	 * the command line syntax for the Maven tree generator.
	 *
	 * @param args array of arguments passed from the command line
	 * @return true if all required arguments are provided and valid, false otherwise
	 */
	public boolean parseArgs(String[] args) {
		CommandLineParser parser = new DefaultParser();
		CommandLine commandLine;

		try {
			commandLine = parser.parse(options, args);

			// Set projects directory
			setProjectsDir(commandLine.getOptionValue("p"));
			// Set output directory
			setOutputDir(commandLine.getOptionValue("o"));
			// Set max recursion depth
			if (commandLine.hasOption("r")) {
				maxDepth = Integer.parseInt(commandLine.getOptionValue("r"));
			}
			// Set default option string
			if (commandLine.hasOption("d")) {
				defaultOption = commandLine.getOptionValue("d");
			}
			// Set special option strings
			if (commandLine.hasOption("s")) {
				String[] specialOptionValues = commandLine.getOptionValues("s");
				specialOptions = new HashMap<>();
				for (String specialOption : specialOptionValues) {
					String[] kv = specialOption.split(",");
					if (kv.length == 2) {
						specialOptions.put(kv[0], kv[1]);
					} else if (kv.length == 1) {
						specialOptions.put(kv[0], "");
					}
				}
			}
		} catch (Exception e) {
			LOG.error("Exception occurred while parsing arguments: {}", e.getMessage());
			new HelpFormatter().printHelp(CMD_LINE_SYNTAX, options);
			return false;
		}
		return true;
	}

	/**
	 * Gets the file for the projects directory as specified by the command line arguments.
	 *
	 * @return file representing the projects directory
	 */
	public File getProjectsDir() {
		return projectsDir;
	}

	/**
	 * Sets the projects directory file using the given path and ensures it is a valid directory.
	 *
	 * @param projectsPath path to the projects directory
	 * @throws IllegalArgumentException if the path is invalid
	 */
	private void setProjectsDir(String projectsPath) {
		projectsDir = new File(projectsPath);
		if (!projectsDir.exists() || !projectsDir.isDirectory()) {
			throw new IllegalArgumentException(
					"Please provide a valid path to the projects directory");
		}
	}

	/**
	 * Gets the file for the output directory as specified by the command line arguments.
	 *
	 * @return file representing the output directory
	 */
	public File getOutputDir() {
		return outputDir;
	}

	/**
	 * Sets the output directory file using the given path and ensures it is a valid directory.
	 *
	 * @param outputPath path to the output directory
	 * @throws IllegalArgumentException if the path is invalid
	 */
	private void setOutputDir(String outputPath) {
		outputDir = new File(outputPath);
		boolean success = outputDir.mkdirs();
		if (!success && !outputDir.isDirectory()) {
			throw new IllegalArgumentException(
					"Please provide a valid path to the output directory");
		}
	}

	/**
	 * Gets the max depth of recursion for the projects directory as specified by the command line
	 * arguments.
	 *
	 * @return max depth of recursion for the projects directory
	 */
	public int getMaxDepth() {
		return maxDepth;
	}

	/**
	 * Gets the default option string for the Maven dependency tree command as specified by the
	 * command line arguments.
	 *
	 * @return default option string for the Maven dependency tree command
	 */
	public String getDefaultOption() {
		return defaultOption;
	}

	/**
	 * Gets the special option strings map for the Maven dependency tree command as specified by the
	 * command line arguments.
	 *
	 * @return special option strings map for the Maven dependency tree command
	 */
	public Map<String, String> getSpecialOptions() {
		return specialOptions;
	}
}
