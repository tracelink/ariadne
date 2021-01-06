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
package com.tracelink.appsec.ariadne.utils;

import java.util.Arrays;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities class for formatting and parsing artifact names.
 */
public class Utils {

	private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

	/**
	 * Gets the full name of the given artifact, formatted as {@code groupId:artifactId:version}.
	 * If the given artifact is not in the correct format already, makes a best effort attempt to
	 * convert it into the correct format.
	 *
	 * @param artifact artifact name to correctly format
	 * @return full, formatted artifact name
	 */
	public static String getFullName(String artifact) {
		return String.join(":", formatArtifact(artifact));
	}

	/**
	 * Parses the given artifact name into groupId, artifactId, and version components, and adds
	 * the three components to an array. If the given artifact is not in the format {@code
	 * groupId:artifactId:version}, makes a best effort attempt to parse each component.
	 *
	 * @param artifact artifact name to parse and format
	 * @return array of artifact name components
	 */
	private static String[] formatArtifact(String artifact) {
		String[] components = Arrays.stream(artifact.split(":")).map(String::trim)
				.toArray(String[]::new);

		while (components.length != 3) {
			switch (components.length) {
				case 1:
					components = artifact.split(" ");
					if (components.length == 1) {
						throw new IllegalArgumentException("Unknown artifact format - " + artifact);
					}
					break;
				case 2:
					if (Character.isDigit(components[1].charAt(0))) {
						// Set group and artifact to be the same
						components = new String[]{components[0], components[0], components[1]};
						LOG.warn("No group/artifact ID: {}", artifact);
					} else {
						// Set version to "null"
						components = new String[]{components[0], components[1], "null"};
						LOG.warn("No version: {}", artifact);
					}
					break;
				default:
					StringBuilder artifactId = new StringBuilder();
					for (int i = 1; i < components.length - 1; i++) {
						if (i != 1) {
							artifactId.append(":");
						}
						artifactId.append(components[i]);

					}
					components = new String[]{
							components[0],
							artifactId.toString(),
							components[components.length - 1]
					};
					LOG.warn("Too many components: {}", artifact);
			}
		}
		return components;
	}

	/**
	 * Gets the groupId and artifactId of the given artifact name, removing any version information.
	 * Assumes that the given artifact is already in the format {@code groupId:artifactId:version}.
	 *
	 * @param artifact artifact to get the name of
	 * @return truncated artifact name
	 */
	public static String getArtifactName(String artifact) {
		return artifact.substring(0, artifact.lastIndexOf(":"));
	}

	/**
	 * Gets the version of the given artifact name. Assumes that the given artifact is already in
	 * the format {@code groupId:artifactId:version}.
	 *
	 * @param artifact artifact to get the version of
	 * @return artifact version
	 */
	public static String getVersion(String artifact) {
		return artifact.substring(artifact.lastIndexOf(":") + 1);
	}

	/**
	 * Splits the given artifact name along colons and dashes to produce a more human-readable
	 * display name. Assumes that the given artifact is already in the format {@code
	 * groupId:artifactId:version}.
	 *
	 * @param artifact artifact to get the display name of
	 * @return artifact display name
	 */
	public static String getDisplayName(String artifact) {
		return Arrays.stream(artifact.split(":")[1].split("-"))
				.map(n -> n.substring(0, 1).toUpperCase() + n.substring(1))
				.collect(Collectors.joining(" "));
	}
}
