const std = @import("std");
const zelda = @import("zelda");

// NOTE: this test will fail if ziglang.org is down!
test "fetch status code of ziglang.org" {
    var response = try zelda.get(std.testing.allocator, "https://ziglang.org");
    defer response.deinit();

    try std.testing.expectEqual(@as(u10, 200), @enumToInt(response.statusCode));
}
