#!/usr/bin/env qore
%new-style

string name = shift ARGV;
string val = shift ARGV;

if (ENV{name} != val) {
    throw "ENV-ERROR", sprintf("env var '%s' has value: '%n', expected: '%n'", name, ENV{name}, val);
}

exit(0);
