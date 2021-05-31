const std = @import("std");
const req = @import("request.zig");
const Client = @import("client.zig").Client;

const OneshotPerformError = Client.InitError || Client.PerformError;
const BasicPerformFunctionPrototype = fn (*std.mem.Allocator, []const u8) OneshotPerformError!req.Response;

fn createOneshotMethod(comptime method: req.Method) BasicPerformFunctionPrototype {
    return struct {
        fn perform(allocator: *std.mem.Allocator, url: []const u8) OneshotPerformError!req.Response {
            var client = try Client.init(allocator, .{});
            defer client.deinit();

            var request = req.Request{
                .method = method,
                .url = url,
            };

            return try client.perform(request);
        }
    }.perform;
}

pub const get = createOneshotMethod(req.Method.GET);

/// Caller is responsible for freeing the returned type
pub fn getJson(
    comptime Type: type,
    parseOptions: std.json.ParseOptions,
    allocator: *std.mem.Allocator,
    url: []const u8,
) !Type {
    var response = try get(allocator, url);
    defer response.deinit(); // we can throw the response away because parse will copy into the structure

    const body = response.body orelse return error.MissingResponseBody;
    return std.json.parse(Type, &std.json.TokenStream.init(body), parseOptions);
}
