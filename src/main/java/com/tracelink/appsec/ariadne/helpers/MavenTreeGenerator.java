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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generates Maven dependency trees for all Maven projects contained in a given directory, up to a
 * specified depth of recursion. All Maven trees are written to a provided output directory.
 * Default option strings and special option strings may be provided to append to the Maven command
 * so that the dependency tree will build successfully. Special options are applied only to matching
 * projects, and if there is no special option provided for a project, the default option will be
 * used.
 *
 * @author mcool
 */
public class MavenTreeGenerator {

	private static final Logger LOG = LoggerFactory.getLogger(MavenTreeGenerator.class);
	private final File outputDir;
	private final int maxDepth;
	private final String defaultOption;
	private final Map<String, String> specialOptions;

	public MavenTreeGenerator(File outputDir, int maxDepth, String defaultOption,
			Map<String, String> specialOptions) {
		this.outputDir = outputDir;
		this.maxDepth = maxDepth;
		this.defaultOption = defaultOption;
		this.specialOptions = specialOptions;
	}

	/**
	 * Builds dependency trees for all Maven projects contained within the given {@link File}, if
	 * the file is a directory. If the file is not a directory, or if the given depth is greater
	 * than the max depth configured for this generator, this method returns without doing anything.
	 * If the given file is a directory and it contains other directories, this method will recurse
	 * to build trees for projects in those files.
	 *
	 * @param file  the file to search for Maven projects
	 * @param depth the current depth of recursion
	 */
	public void buildTrees(File file, int depth) {
		// Stop recursion if this is not a directory or we have exceeded the maximum search depth
		if (depth > maxDepth || !file.isDirectory()) {
			return;
		}

		// Get all files for this directory
		File[] innerFiles = file.listFiles();
		if (innerFiles == null) {
			return;
		}
		if (Arrays.stream(innerFiles).noneMatch(f -> f.getName().equals("pom.xml"))) {
			// If there is no POM file in this directory, recursively search other directories
			// until max depth reached
			if (depth == 1) {
				LOG.warn("No POM file: {}", file.getAbsolutePath());
			}
			Arrays.stream(innerFiles).forEach(f -> buildTrees(f, depth + 1));
		} else {
			// If there is a POM file in this directory, attempt to build the Maven dependency tree
			String outputPath = outputDir.getAbsolutePath() + "/" + file.getName() + ".txt";
			String options = specialOptions.getOrDefault(file.getName(), defaultOption);

			ProcessBuilder processBuilder = new ProcessBuilder()
					// Uncomment this line to see Maven build output in console
					// .inheritIO()
					.directory(file);
			if (options.length() == 0) {
				processBuilder.command("mvn", "dependency:tree", "-DappendOutput=true",
						"-DoutputFile=" + outputPath);
			} else {
				processBuilder.command("mvn", "dependency:tree", "-DappendOutput=true",
						"-DoutputFile=" + outputPath, options);
			}
			try {
				// Run command
				Process process = processBuilder.start();
				int exitCode = process.waitFor();
				// Log failure or success
				if (exitCode != 0 && depth == 1) {
					LOG.warn("Build failed: {}", file.getAbsolutePath());
				} else {
					LOG.info("Build success: {}", file.getAbsolutePath());
				}
			} catch (Exception e) {
				LOG.warn("Exception occurred: {}", e.getMessage());
			}
		}
	}

	/**
	 * Identifies parent projects for all Maven projects contained within the given {@link File},
	 * if the file is a directory. If the file is not a directory, or if the given depth is greater
	 * than the max depth configured for this generator, this method returns without doing
	 * anything. If the given file is a directory, this method will recurse to identify parents for
	 * all Maven projects in the inner files. Writes all parent-child relationships to a file in
	 * the format of a Maven dependency tree.
	 *
	 * @param file  the file to search for Maven projects
	 * @param depth the current depth of recursion
	 */
	public void identifyParents(File file, int depth) {
		// Stop recursion if this is not a directory or we have exceeded the maximum search depth
		if (depth > maxDepth || !file.isDirectory()) {
			return;
		}

		// Get all files for this directory
		File[] innerFiles = file.listFiles();
		if (innerFiles == null) {
			return;
		}
		// If there is a POM file in this directory, check if it specifies a parent
		if (Arrays.stream(innerFiles).anyMatch(f -> f.getName().equals("pom.xml"))) {
			String options = specialOptions.getOrDefault(file.getName(), defaultOption);

			// Parse parent and child groupId, artifactId, and version
			String pGroupId = evaluateArtifactExpression(file, "project.parent.groupId", options);
			if (pGroupId != null && !pGroupId.equals("null object or invalid expression")
					&& !pGroupId.contains("[ERROR]")) {
				String pArtifactId = evaluateArtifactExpression(file,
						"project.parent.artifactId",
						options);
				String pVersion = evaluateArtifactExpression(file, "project.parent.version",
						options);
				String pName = String.join(":", pGroupId, pArtifactId, pVersion);

				String cGroupId = evaluateArtifactExpression(file, "project.groupId", options);
				String cArtifactId = evaluateArtifactExpression(file, "project.artifactId",
						options);
				String cVersion = evaluateArtifactExpression(file, "project.version", options);
				String cName = String.join(":", cGroupId, cArtifactId, cVersion);

				LOG.info("{} ---> {}", cName, pName);

				// Write parent-child relationship to file
				String outputPath = outputDir.getAbsolutePath() + "/parents.txt";
				try {
					BufferedWriter writer = new BufferedWriter(
							new FileWriter(outputPath, true));
					writer.write(cName);
					writer.newLine();
					writer.write("\\- ");
					writer.write(pName);
					writer.newLine();
					writer.close();
				} catch (IOException e) {
					throw new RuntimeException(e.getMessage());
				}
			}
		}
		// Perform recursion on inner files
		Arrays.stream(innerFiles).forEach(f -> identifyParents(f, depth + 1));
	}

	/**
	 * Evaluates a Maven artifact expression on a given Maven project.
	 *
	 * @param file       the directory to run the command from
	 * @param expression the Maven expression to evaluate
	 * @param options    option string to append to the Maven command so that evaluation succeeds
	 * @return string representing the evaluation of the expression
	 */
	private String evaluateArtifactExpression(File file, String expression, String options) {
		ProcessBuilder processBuilder = new ProcessBuilder().directory(file);
		if (options.length() == 0) {
			processBuilder.command("mvn", "help:evaluate", "-Dexpression=" + expression, "-q",
					"-DforceStdout");
		} else {
			processBuilder.command("mvn", "help:evaluate", "-Dexpression=" + expression, "-q",
					"-DforceStdout", options);
		}
		String result = null;
		try {
			Process process = processBuilder.start();
			try (BufferedReader br = new BufferedReader(
					new InputStreamReader(process.getInputStream()))) {
				result = br.readLine();
			}
		} catch (IOException e) {
			LOG.warn("Exception occurred: {}", e.getMessage());
		}
		return result;
	}
}
