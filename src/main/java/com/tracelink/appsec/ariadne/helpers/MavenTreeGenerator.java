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

class MavenTreeGenerator {

	private static final Logger LOG = LoggerFactory.getLogger(MavenTreeGenerator.class);
	private final File outputDir;
	private final int maxDepth;
	private final String defaultOption;
	private final Map<String, String> specialOptions;

	MavenTreeGenerator(File outputDir, int maxDepth, String defaultOption,
			Map<String, String> specialOptions) {
		this.outputDir = outputDir;
		this.maxDepth = maxDepth;
		this.defaultOption = defaultOption;
		this.specialOptions = specialOptions;
	}

	void buildTrees(File file, int depth) {
		// Stop recursion if this is not a directory or we have exceeded the maximum search depth
		if (depth > maxDepth || !file.isDirectory()) {
			return;
		}

		// Get all files for this directory
		File[] innerFiles = file.listFiles();
		if (innerFiles == null) {
			return;
		}
		// If there is no POM file in this directory, recursively search other directories until max depth reached
		if (Arrays.stream(innerFiles).noneMatch(f -> f.getName().equals("pom.xml"))) {
			if (depth == 1) {
				LOG.warn("No POM file: {}", file.getAbsolutePath());
			}
			Arrays.stream(innerFiles).forEach(
					f -> buildTrees(f, depth + 1));
		} else {
			// There is a POM file in this directory. Attempt to build Maven dependency tree
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
				Process process = processBuilder.start();
				int exitCode = process.waitFor();
				// If build failed, add to list of failures
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

	void identifyParents(File file, int depth) {
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

		Arrays.stream(innerFiles).forEach(f -> identifyParents(f, depth + 1));
	}

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
