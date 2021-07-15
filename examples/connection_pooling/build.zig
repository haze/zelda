const std = @import("std");
const Pkg = std.build.Pkg;

pub const pkgs = struct {
    pub const hzzp = Pkg{
        .name = "hzzp",
        .path = .{ .path = "../../hzzp/src/main.zig" },
    };

    pub const zuri = Pkg{
        .name = "zuri",
        .path = .{ .path = "../../zuri/src/zuri.zig" },
    };

    pub const iguanaTLS = Pkg{
        .name = "iguanaTLS",
        .path = .{ .path = "../../iguanaTLS/src/main.zig" },
    };

    pub const zelda = Pkg{
        .name = "zelda",
        .path = .{ .path = "../../src/main.zig" },
        .dependencies = &[_]Pkg{
            hzzp, zuri, iguanaTLS,
        },
    };
};

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("connection_pooling", "src/main.zig");
    exe.linkLibC();
    exe.addPackage(pkgs.zelda);
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
