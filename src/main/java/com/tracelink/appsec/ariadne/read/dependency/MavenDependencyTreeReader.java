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
package com.tracelink.appsec.ariadne.read.dependency;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class MavenDependencyTreeReader implements DependencyReader {

	private final File[] files;
	private final Pattern directDepPattern = Pattern.compile("[+\\\\]- .*");
	private final Pattern transitiveDepPattern = Pattern.compile("(\\| {2}| {3}).*");

	public MavenDependencyTreeReader(String path) throws FileNotFoundException {
		File file = new File(path);
		if (!file.exists()) {
			throw new FileNotFoundException(
					"Please provide a valid path to the dependency tree(s)");
		}
		if (file.isDirectory()) {
			files = file.listFiles();
		} else {
			files = new File[]{file};
		}
	}

	@Override
	public List<Map.Entry<String, String>> readDependencies() throws IOException {
		List<Map.Entry<String, String>> dependencies = new ArrayList<>();

		for (File file : files) {
			try (BufferedReader fileReader = new BufferedReader(new FileReader(file))) {
				List<String> lines = fileReader.lines().collect(Collectors.toList());
				dependencies.addAll(readMavenTree(lines));
			}
		}
		return dependencies;
	}

	private List<Map.Entry<String, String>> readMavenTree(List<String> tree) {
		List<Map.Entry<String, String>> dependencies = new ArrayList<>();
		String parent = null;
		List<String> childTree = new ArrayList<>();

		for (String line : tree) {

			if (directDepPattern.matcher(line).matches()) {
				// Found a direct dependency
				// Recursively parse child tree, if there are transitive dependency
				if (childTree.size() > 1) {
					dependencies.addAll(readMavenTree(childTree));
				}
				// Initialize new child tree
				String child = line.substring(3);
				childTree = new ArrayList<>();
				childTree.add(child);
				// Add direct dependency tuple to master list
				dependencies.add(new AbstractMap.SimpleEntry<>(parent, formatArtifactName(child)));
			} else if (transitiveDepPattern.matcher(line).matches()) {
				// Found a transitive dependency
				childTree.add(line.substring(3));
			} else {
				// Found a new parent
				parent = formatArtifactName(line);
			}
		}

		if (childTree.size() > 1) {
			dependencies.addAll(readMavenTree(childTree));
		}
		return dependencies;
	}

	private String formatArtifactName(String artifact) {
		String[] components = artifact.split(":");
		String[] updatedComponents = new String[3];
		for (int i = 0; i < components.length; i++) {
			if (i == 2 || i > 3) {
				continue;
			}
			int index = i < 2 ? i : i - 1;
			updatedComponents[index] = components[i];
		}
		return String.join(":", updatedComponents).trim();
	}
}
