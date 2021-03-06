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

import com.tracelink.appsec.ariadne.utils.Utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PomExplorerReader implements DependencyReader {
    private File file;

    public PomExplorerReader(String path) throws FileNotFoundException {
        file = new File(path);
        if (!file.exists() || file.isDirectory()) {
            throw new FileNotFoundException("Please provide a valid path to the Pom Explorer data.");
        }
    }

    @Override
    public List<Map.Entry<String, String>> readDependencies() throws IOException {
        List<Map.Entry<String, String>> dependencies = new ArrayList<>();

        try (BufferedReader fileReader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = fileReader.readLine()) != null) {
                String[] components = line.split(",");
                String parent = components[0];
                String child = components[2];
                if (parent.equals("from")) {
                    continue;
                }
                dependencies.add(new AbstractMap.SimpleEntry<>(Utils.getFullName(parent), Utils.getFullName(child)));
            }
        }
        return dependencies;
    }
}
