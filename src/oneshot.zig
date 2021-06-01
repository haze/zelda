const std = @import("std");
const req = @import("request.zig");
const Client = @import("client.zig").Client;

const BasicPerformFunctionPrototype = fn (*std.mem.Allocator, []const u8) !req.Response;

pub fn get(allocator: *std.mem.Allocator, url: []const u8) !req.Response {
    var client = try Client.init(allocator, .{});
    defer client.deinit();

    var request = req.Request{
        .method = .GET,
        .url = url,
    };

    return try client.perform(request);
}

pub fn post(allocator: *std.mem.Allocator, url: []const u8, body: ?req.Body) !req.Response {
    var client = try Client.init(allocator, .{});
    defer client.deinit();

    var request = req.Request{
        .method = .POST,
        .url = url,
        .body = body,
    };

    return try client.perform(request);
}

/// Caller is responsible for freeing the returned type
pub fn postAndParseResponse(
    comptime Type: type,
    parseOptions: std.json.ParseOptions,
    allocator: *std.mem.Allocator,
    url: []const u8,
    body: ?req.Body,
) !Type {
    var response = try post(allocator, url, body);
    defer response.deinit(); // we can throw the response away because parse will copy into the structure

    const responseBytes = response.body orelse return error.MissingResponseBody;
    return std.json.parse(Type, &std.json.TokenStream.init(responseBytes), parseOptions);
}

pub fn postJson(allocator: *std.mem.Allocator, url: []const u8, jsonValue: anytype, stringifyOptions: std.json.StringifyOptions) !req.Response {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    var writer = buffer.writer();
    try std.json.stringify(jsonValue, stringifyOptions, writer);
    return post(allocator, url, req.Body{ .kind = .JSON, .bytes = buffer.items });
}

/// Caller is responsible for caling std.json.parseFree (with the same parseOptions) on the returned value
const PostAndParseOptions = struct {
    allocator: *std.mem.Allocator,
    parseOptions: std.json.ParseOptions = .{},
    stringifyOptions: std.json.StringifyOptions = .{},
};
fn parseOptionsWithAllocator(allocator: *std.mem.Allocator, options: std.json.ParseOptions) std.json.ParseOptions {
    var newOpts = options;
    newOpts.allocator = allocator;
    return newOpts;
}

pub fn postJsonAndParseResponse(comptime OutputType: type, url: []const u8, jsonValue: anytype, options: PostAndParseOptions) !OutputType {
    var response = try postJson(options.allocator, url, jsonValue, options.stringifyOptions);
    defer response.deinit();

    const responseBytes = response.body orelse return error.MissingResponseBody;
    return std.json.parse(OutputType, &std.json.TokenStream.init(responseBytes), parseOptionsWithAllocator(options.allocator, options.parseOptions));
}

/// Caller is responsible for freeing the returned type
pub fn getAndParseResponse(
    comptime Type: type,
    parseOptions: std.json.ParseOptions,
    allocator: *std.mem.Allocator,
    url: []const u8,
) !Type {
    var response = try get(allocator, url);
    defer response.deinit(); // we can throw the response away because parse will copy into the structure

    const responseBody = response.body orelse return error.MissingResponseBody;
    return std.json.parse(Type, &std.json.TokenStream.init(responseBody), parseOptions);
}
