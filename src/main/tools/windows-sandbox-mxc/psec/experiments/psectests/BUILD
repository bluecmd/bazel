# Minimal tests of each kind, to run under --spawn_strategy=windows-sandbox (not part of the tree).
load("@rules_cc//cc:cc_test.bzl", "cc_test")
load("@rules_java//java:java_test.bzl", "java_test")
load("@rules_python//python:py_test.bzl", "py_test")
load("@rules_shell//shell:sh_test.bzl", "sh_test")

cc_test(
    name = "cc",
    srcs = ["cc_test.cc"],
    data = ["data.txt"],
    size = "small",
)

java_test(
    name = "java",
    srcs = ["JavaTest.java"],
    main_class = "JavaTest",
    use_testrunner = False,
    data = ["data.txt"],
    size = "small",
)

py_test(
    name = "py",
    srcs = ["py_test.py"],
    deps = ["@rules_python//python/runfiles"],
    main = "py_test.py",
    data = ["data.txt"],
    size = "small",
)

sh_test(
    name = "sh",
    srcs = ["sh_test.sh"],
    data = ["data.txt"],
    size = "small",
)
