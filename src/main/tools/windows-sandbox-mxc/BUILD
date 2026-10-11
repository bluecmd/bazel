load("@rules_cc//cc:cc_binary.bzl", "cc_binary")

package(default_visibility = ["//src:__subpackages__"])

# Adapter that lets --experimental_use_windows_sandbox drive Microsoft
# Execution Containers (wxc-exec.exe). Experimental; see README.md.
cc_binary(
    name = "BazelSandbox",
    srcs = ["BazelSandbox.c"],
    target_compatible_with = ["@platforms//os:windows"],
)
