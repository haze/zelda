const std = @import("std");
const Pkg = std.build.Pkg;

pub const pkgs = struct {
    pub const hzzp = Pkg{
        .name = "hzzp",
        .path = .{ .path = "hzzp/src/main.zig" },
    };

    pub const zuri = Pkg{
        .name = "zuri",
        .path = .{ .path = "zuri/src/zuri.zig" },
    };

    pub const iguanaTLS = Pkg{
        .name = "iguanaTLS",
        .path = .{ .path = "iguanaTLS/src/main.zig" },
    };

    pub const zelda = Pkg{
        .name = "zelda",
        .path = .{ .path = "src/main.zig" },
        .dependencies = &[_]Pkg{
            hzzp, zuri, iguanaTLS,
        },
    };
};

pub fn register(step: *std.build.LibExeObjStep) void {
    step.addPackage(pkgs.zelda);
}

// Hijacked from https://github.com/lithdew/hyperia/blob/master/build.zig
pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const test_step = b.step("test", "Run library tests.");
    const test_filter = b.option([]const u8, "test-filter", "Test filter");
    const sanitize_thread = b.option(bool, "sanitize-thread", "Enable ThreadSanitizer") orelse false;

    const file = b.addTest("src/tests.zig");
    file.linkLibC();
    file.sanitize_thread = sanitize_thread;
    file.setTarget(target);
    file.setBuildMode(mode);
    register(file);

    if (test_filter != null) {
        file.setFilter(test_filter.?);
    }

    test_step.dependOn(&file.step);

    // const lib = b.addStaticLibrary("zelda", "src/main.zig");
    // lib.addPackagePath("iguanaTLS", "iguanaTLS/src/main.zig");
    // lib.addPackagePath("hzzp", "hzzp/src/main.zig");
    // lib.addPackagePath("zuri", "zuri/src/zuri.zig");
    // lib.setBuildMode(mode);
    // lib.install();

    // var main_tests = b.addTest("src/tests.zig");
    // main_tests.addPackage()
    // main_tests.setBuildMode(mode);

    // const test_step = b.step("test", "Run library tests");
    // test_step.dependOn(&main_tests.step);
}
