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
package com.tracelink.appsec.ariadne.model;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Represents the version of an internal artifact. Keeps track of dependencies of or upon a
 * particular version of an artifact.
 */
class InternalVersion implements Comparable<InternalVersion> {

	private final String version;
	private final Set<Artifact> parents = new TreeSet<>();
	private final Set<Artifact> children = new TreeSet<>();

	InternalVersion(String version) {
		this.version = version;
	}

	/**
	 * Gets a string representing the version of an artifact.
	 *
	 * @return version string
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Gets the number of artifacts that depend on this version.
	 *
	 * @return number of connections
	 */
	public int getConnections() {
		return parents.size();
	}

	/**
	 * Determines whether this version depends on the given child artifact.
	 *
	 * @param child string representing a child artifact
	 * @return true if this version depends on the given child artifact, false otherwise
	 */
	public boolean hasChild(String child) {
		return children.stream().anyMatch(a -> a.getName().equals(child));
	}

	/**
	 * Adds the given parent {@link Artifact} to this version.
	 *
	 * @param parent the parent artifact
	 */
	public void addParent(Artifact parent) {
		parents.add(parent);
	}

	/**
	 * Adds the given child {@link Artifact} to this version.
	 *
	 * @param child the child artifact
	 */
	public void addChild(Artifact child) {
		children.add(child);
	}

	/**
	 * Assigns a tier to all parents of this version.
	 *
	 * @param tier    current tier
	 * @param root    root artifact of the vulnerability
	 * @param direct  direct vulnerable dependency of this artifact
	 * @param visited list of previously visited artifacts
	 * @param updated list of parents that have already been updated
	 * @param cycles  set of artifacts that are in a cycle to determine which tier to assign
	 */
	public void assignTier(int tier, String root, String direct, List<String> visited,
			List<Artifact> updated, Set<String> cycles) {
		parents.forEach(parent -> {
			// Don't revisit the ones updated by other versions of this artifact
			if (!updated.contains(parent)) {
				updated.add(parent);
				parent.assignTier(cycles.contains(parent.getName()) ? tier : tier + 1, root, direct,
						visited);
			}
		});
	}

	/**
	 * Identifies cycles for all parents of this version.
	 *
	 * @param visited list of previously visited artifacts
	 * @param updated list of parents that have already been updated
	 */
	public void findCycles(List<String> visited, List<Artifact> updated) {
		for (Artifact parent : parents) {
			// Don't visit the ones updated in other versions of this artifact
			if (!updated.contains(parent)) {
				updated.add(parent);
				parent.findCycles(visited);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int compareTo(InternalVersion o) {
		String[] thisComponents = version.split("-", 2);
		String[] oComponents = o.getVersion().split("-", 2);

		int compareNum = compareVersionNum(thisComponents[0], oComponents[0]);
		if (compareNum != 0) {
			return compareNum;
		}

		if (thisComponents.length == 2 && oComponents.length == 2) {
			return compareBuildNum(thisComponents[1], oComponents[1]);
		} else if (thisComponents.length == 2) {
			return -1;
		} else if (oComponents.length == 2) {
			return 1;
		} else {
			return 0;
		}
	}

	/**
	 * Helper to compare version numbers and determine which of the two given versions is newer.
	 *
	 * @param s1 first version string to compare
	 * @param s2 second version string to compare
	 * @return less than zero if the first version comes before the second version, zero if the two
	 * versions match, and greater than zero if the first version comes after the second version
	 */
	private int compareVersionNum(String s1, String s2) {
		String versionNumRegex = "\\d+(\\.\\d+)*";
		if (s1.matches(versionNumRegex) && s2.matches(versionNumRegex)) {
			String[] s1components = s1.split("\\.");
			String[] s2components = s2.split("\\.");

			for (int i = 0; i < s1components.length && i < s2components.length; i++) {
				int compareDigit =
						Integer.parseInt(s2components[i]) - Integer.parseInt(s1components[i]);
				if (compareDigit != 0) {
					return compareDigit;
				}
			}
			return s2components.length - s1components.length;
		} else if (s1.matches(versionNumRegex)) {
			return -1;
		} else if (s2.matches(versionNumRegex)) {
			return 1;
		} else {
			return s2.compareTo(s1);
		}
	}

	/**
	 * Helper to compare build numbers that are attached to version strings.
	 *
	 * @param s1 first build number to compare
	 * @param s2 second build number to compare
	 * @return less than zero if the first build number comes before the second build number, zero
	 * if the two build numbers match, and greater than zero if the first build number comes after
	 * the second build number
	 */
	private int compareBuildNum(String s1, String s2) {
		if (s1.equals(s2)) {
			return 0;
		} else if (s1.contains("SNAPSHOT")) {
			return -1;
		} else if (s2.contains("SNAPSHOT")) {
			return 1;
		} else {
			return Integer.parseInt(s2) - Integer.parseInt(s1);
		}
	}
}
