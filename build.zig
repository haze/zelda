const std = @import("std");
const zig_libressl = @import("zig-libressl/build.zig");
const Pkg = std.build.Pkg;

pub const pkgs = struct {
    pub const hzzp = Pkg{
        .name = "hzzp",
        .path = std.build.FileSource.relative("hzzp/src/main.zig"),
    };

    pub const zuri = Pkg{
        .name = "zuri",
        .path = std.build.FileSource.relative("zuri/src/zuri.zig"),
    };

    pub const libressl = Pkg{
        .name = "zig-libressl",
        .path = std.build.FileSource.relative("zig-libressl/src/main.zig"),
    };

    pub const zelda = Pkg{
        .name = "zelda",
        .path = .{ .path = "src/main.zig" },
        .dependencies = &[_]Pkg{
            hzzp, zuri, libressl,
        },
    };
};

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const test_step = b.step("test", "Run library tests.");
    const maybe_test_filter = b.option([]const u8, "test-filter", "Test filter");
    const sanitize_thread = b.option(bool, "sanitize-thread", "Enable ThreadSanitizer") orelse false;

    const create_test_step = b.addTest("src/tests.zig");
    create_test_step.linkLibC();
    create_test_step.sanitize_thread = sanitize_thread;
    create_test_step.setTarget(target);
    create_test_step.setBuildMode(mode);
    create_test_step.addPackage(pkgs.zelda);
    zig_libressl.useLibreSslForStep(b, create_test_step, "zig-libressl/libressl");

    if (maybe_test_filter) |test_filter| {
        create_test_step.setFilter(test_filter);
    }

    test_step.dependOn(&create_test_step.step);
}
