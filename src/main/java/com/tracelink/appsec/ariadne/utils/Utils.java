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

public class Utils {

	private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

	/*
	 * Assume bad formatting
	 */

	public static String getFullName(String artifact) {
		return String.join(":", formatArtifact(artifact));
	}

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

	/*
	 * Assume good formatting (groupId:artifactId:version)
	 */

	public static String getArtifactName(String artifact) {
		return artifact.substring(0, artifact.lastIndexOf(":"));
	}

	public static String getVersion(String artifact) {
		return artifact.substring(artifact.lastIndexOf(":") + 1);
	}

	public static String getDisplayName(String artifact) {
		return Arrays.stream(artifact.split(":")[1].split("-"))
				.map(n -> n.substring(0, 1).toUpperCase() + n.substring(1))
				.collect(Collectors.joining(" "));
	}
}
