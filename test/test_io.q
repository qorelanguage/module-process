#!/usr/bin/env qore
%new-style

# WARNING: it hangs until stdin data are provided!
string s = Qore::stdin.readLine();
Qore::stdout.write(s);

Qore::stderr.write("123");
Qore::stderr.sync();
s = Qore::stdin.readLine(False);

Qore::stdout.write(s);
Qore::stderr.write(s);
sleep(2s);
s = Qore::stdin.readLine(False);

int retCode = int(s);

exit(retCode);
