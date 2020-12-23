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

class InternalVersion implements Comparable<InternalVersion> {

	private final String version;
	private final Set<Artifact> parents = new TreeSet<>();
	private final Set<Artifact> children = new TreeSet<>();

	InternalVersion(String version) {
		this.version = version;
	}

	public String getVersion() {
		return version;
	}

	int getConnections() {
		return parents.size();
	}

	boolean hasChild(String child) {
		return children.stream().anyMatch(a -> a.getName().equals(child));
	}

	void addParent(Artifact parent) {
		parents.add(parent);
	}

	void addChild(Artifact child) {
		children.add(child);
	}

	void assignTier(int tier, String root, String direct, List<String> visited,
			List<Artifact> updated,
			Set<String> cycles) {
		parents.forEach(parent -> {
			// Don't visit the ones updated in other versions of this artifact
			if (!updated.contains(parent)) {
				updated.add(parent);
				parent.assignTier(cycles.contains(parent.getName()) ? tier : tier + 1, root, direct,
						visited);
			}
		});
	}

	void findCycles(List<String> visited, List<Artifact> updated) {
		for (Artifact parent : parents) {
			// Don't visit the ones updated in other versions of this artifact
			if (!updated.contains(parent)) {
				updated.add(parent);
				parent.findCycles(visited);
			}
		}
	}

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
