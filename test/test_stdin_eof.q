#!/usr/bin/env qore
%new-style

# Read all lines from stdin until EOF, sort them, and print
list<string> lines = ();
while (True) {
    *string line = stdin.readLine(False);
    if (!exists line) {
        break;
    }
    lines += line;
}

lines = sort(lines);
for (int i = 0; i < lines.size(); i++) {
    stdout.print(lines[i]);
    if (i < lines.size() - 1) {
        stdout.print("\n");
    }
}

exit(0);
