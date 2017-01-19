#!/usr/bin/env qore
%new-style

# WARNING: it hangs until stdin data are provided!
string s = Qore::stdin.readLine();
Qore::stdout.write(s);

Qore::stderr.write("my error 0\n");
sleep(2s);
Qore::stderr.write("my error 1\n");

exit(0);
