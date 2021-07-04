const std = @import("std");
const builtin = @import("builtin");

const root = @import("main.zig");
const req = @import("request.zig");
const Request = req.Request;
const Response = req.Response;

const zuri = root.zuri;
const hzzp = root.hzzp;
const iguanaTLS = root.iguanaTLS;

pub const root_ca = struct {
    const pem = @embedFile("../cacert.pem");
    var cert_chain: ?iguanaTLS.x509.CertificateChain = null;

    /// Initializes the bundled root certificates
    /// This is a shared chain that's used whenever an PEM is not passed in
    pub fn preload(allocator: *std.mem.Allocator) !void {
        std.debug.assert(cert_chain == null);
        var fbs = std.io.fixedBufferStream(pem);
        cert_chain = try iguanaTLS.x509.CertificateChain.from_pem(allocator, fbs.reader());
    }

    pub fn deinit() void {
        cert_chain.?.deinit();
        cert_chain = null;
    }
};

fn preloadRootCA() void {
    var maybeTimer = std.time.Timer.start() catch |e| blk: {
        root.logger.err("Failed to start preloadRootCA timer: {s}", .{@errorName(e)});
        break :blk null;
    };
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    root_ca.preload(std.heap.c_allocator) catch |e| {
        root.logger.err("Failed to initialize Root CA: {s}", .{@errorName(e)});
        return;
    };
    if (maybeTimer) |timer|
        root.logger.debug("Loaded Root CA in {d:.2}s", .{@intToFloat(f64, timer.read()) / @intToFloat(f64, std.time.ns_per_s)})
    else
        root.logger.debug("Loaded Roor CA", .{});
}

var initRootCA = std.once(preloadRootCA);

pub const Client = struct {
    const Self = @This();
    const HzzpSSLResponseParser = hzzp.parser.response.ResponseParser(IguanaClient.Reader);
    const HzzpResponseParser = hzzp.parser.response.ResponseParser(std.net.Stream.Reader);
    // pub const PerformError = error{ MissingStatus, ExpectedHeaders, Overflow } || std.os.ConnectError || std.os.SocketError || GetAddrInfoError || iguanaTLS.ClientConnectError(.default, std.net.Stream.Reader, std.net.Stream.Writer, false) || zuri.Uri.Error || std.fmt.BufPrintError || HzzpResponseParser.NextError || HzzpSSLResponseParser.NextError || Request.Error;
    // pub const InitError = error{} || std.mem.Allocator.Error || iguanaTLS.x509.DecodeDERError(std.io.Reader(*std.io.FixedBufferStream([]const u8), std.io.FixedBufferStream([]const u8).ReadError, std.io.FixedBufferStream([]const u8).read));

    pub const IguanaClient = iguanaTLS.Client(std.net.Stream.Reader, std.net.Stream.Writer, iguanaTLS.ciphersuites.all, false);
    pub const HzzpSSLClient = hzzp.base.client.BaseClient(IguanaClient.Reader, IguanaClient.Writer);
    pub const HzzpClient = hzzp.base.client.BaseClient(std.net.Stream.Reader, std.net.Stream.Writer);

    pub const State = union(enum) {
        Created,
        ConnectedSSL: struct {
            tcpConnection: std.net.Stream,
            tunnel: IguanaClient,
            client: HzzpSSLClient,
        },
        Connected: struct {
            tcpConnection: std.net.Stream,
            client: HzzpClient,
        },
        Shutdown,

        const NextError = HzzpSSLResponseParser.NextError || HzzpResponseParser.NextError;

        const PayloadReader = union(enum) {
            SSLReader: HzzpSSLClient.PayloadReader,
            Reader: HzzpClient.PayloadReader,
        };

        pub fn payloadReader(self: *State) PayloadReader {
            return switch (self.*) {
                .ConnectedSSL => |*state| .{ .SSLReader = state.client.reader() },
                .Connected => |*state| .{ .Reader = state.client.reader() },
                else => unreachable,
            };
        }

        pub fn next(self: *State) NextError!?hzzp.parser.response.Event {
            return switch (self.*) {
                .ConnectedSSL => |*state| state.client.next(),
                .Connected => |*state| state.client.next(),
                else => unreachable,
            };
        }

        pub fn writePayload(self: *State, maybeData: ?[]const u8) !void {
            if (maybeData) |data|
                root.logger.debug("Attempting to write {} byte payload", .{data.len})
            else
                root.logger.debug("Attempting to write null payload", .{});
            return switch (self.*) {
                .ConnectedSSL => |*state| state.client.writePayload(maybeData),
                .Connected => |*state| state.client.writePayload(maybeData),
                else => unreachable,
            };
        }

        pub fn finishHeaders(self: *State) !void {
            root.logger.debug("Attempting to finish headers", .{});
            return switch (self.*) {
                .ConnectedSSL => |*state| state.client.finishHeaders(),
                .Connected => |*state| state.client.finishHeaders(),
                else => unreachable,
            };
        }

        pub fn writeHeaderValue(self: *State, name: []const u8, value: []const u8) !void {
            root.logger.debug("Attempting to set header: \"{s}\" = \"{s}\"", .{ name, value });
            return switch (self.*) {
                .ConnectedSSL => |*state| state.client.writeHeaderValue(name, value),
                .Connected => |*state| state.client.writeHeaderValue(name, value),
                else => unreachable,
            };
        }

        pub fn writeStatusLine(self: *State, method: []const u8, path: []const u8) !void {
            root.logger.debug("Attempting to write status line (method={s}, path={s})", .{ method, path });
            return switch (self.*) {
                .ConnectedSSL => |*state| state.client.writeStatusLine(method, path),
                .Connected => |*state| state.client.writeStatusLine(method, path),
                else => unreachable,
            };
        }
    };

    allocator: *std.mem.Allocator,
    state: State,
    userProvidedChain: bool,
    trustChain: ?iguanaTLS.x509.CertificateChain,
    clientReadBuffer: []u8,
    userAgent: ?[]u8,

    pub fn deinit(self: *Self) void {
        if (self.trustChain) |chain|
            chain.deinit();
        if (self.userAgent) |userAgent|
            self.allocator.free(userAgent);
        self.allocator.free(self.clientReadBuffer);
        self.allocator.destroy(self);
    }

    /// if a user agent is provided, it will be copied into the client and free'd once deinit is called
    pub fn init(allocator: *std.mem.Allocator, options: struct {
        pem: ?[]const u8 = null,
        userAgent: ?[]const u8 = null,
    }) !*Self {
        var client: *Self = try allocator.create(Self);
        errdefer allocator.destroy(client);

        client.allocator = allocator;
        client.state = .Created;

        client.userProvidedChain = options.pem != null;
        client.clientReadBuffer = try allocator.alloc(u8, 1 << 13);
        errdefer allocator.free(client.clientReadBuffer);

        if (options.pem) |pem| {
            var fbs = std.io.fixedBufferStream(pem);
            client.trustChain = try iguanaTLS.x509.CertificateChain.from_pem(allocator, fbs.reader());
        } else {
            initRootCA.call();
            client.trustChain = null;
        }

        if (options.userAgent) |userAgent| {
            client.userAgent = try allocator.alloc(u8, userAgent.len);
            std.mem.copy(u8, client.userAgent.?, userAgent);
        } else {
            client.userAgent = null;
        }

        return client;
    }

    pub fn perform(self: *Self, request: Request) !Response {
        var uri = try zuri.Uri.parse(request.url, false);
        const port: u16 = if (uri.port == null) if (std.mem.startsWith(u8, uri.scheme, "https")) @as(u16, 443) else @as(u16, 80) else uri.port.?;
        var tunnelHostBuf: [1 << 8]u8 = undefined;
        var tunnelHost: []const u8 = undefined;
        var isSSL = port == 443;
        var tcpConnection = switch (uri.host) {
            .name => |host| blk: {
                if (host.len == 0) return error.MissingScheme;
                tunnelHost = host;
                root.logger.debug("Opening tcp connection to {s}:{}...", .{ host, port });
                break :blk try std.net.tcpConnectToHost(self.allocator, host, port);
            },
            .ip => |addr| blk: {
                // if we have an ip, print it as the host for the iguanaTLS client
                tunnelHost = try std.fmt.bufPrint(&tunnelHostBuf, "{}", .{addr});
                root.logger.debug("Opening tcp connection to {s}:{}...", .{ tunnelHost, port });
                break :blk try std.net.tcpConnectToAddress(addr);
            },
        };

        root.logger.debug("Opening TLS tunnel...", .{});
        var chain = if (self.trustChain) |chain|
            chain.data.items
        else
            root_ca.cert_chain.?.data.items;

        if (isSSL) {
            var tunnel = try iguanaTLS.client_connect(.{
                .reader = tcpConnection.reader(),
                .writer = tcpConnection.writer(),
                .cert_verifier = .default,
                .trusted_certificates = chain,
                .temp_allocator = self.allocator,
            }, tunnelHost);
            root.logger.debug("Tunnel open, creating client now", .{});
            var client = hzzp.base.client.create(self.clientReadBuffer, tunnel.reader(), tunnel.writer());
            self.state = .{ .ConnectedSSL = .{
                .tcpConnection = tcpConnection,
                .tunnel = tunnel,
                .client = client,
            } };
            root.logger.debug("Client created...", .{});
        } else {
            var client = hzzp.base.client.create(self.clientReadBuffer, tcpConnection.reader(), tcpConnection.writer());
            self.state = .{ .Connected = .{
                .tcpConnection = tcpConnection,
                .client = client,
            } };
        }
        root.logger.debug("Opened TLS tunnel", .{});

        root.logger.debug("path={s} query={s} fragment={s}", .{ uri.path, uri.query, uri.fragment });
        var path = if (std.mem.trim(u8, uri.path, " ").len == 0) "/" else uri.path;
        if (std.mem.trim(u8, uri.query, " ").len == 0) {
            try self.state.writeStatusLine(@tagName(request.method), path);
        } else {
            var status = try std.fmt.allocPrint(self.allocator, "{s}?{s}", .{ path, uri.query });
            try self.state.writeStatusLine(@tagName(request.method), status);
            self.allocator.free(status);
        }

        try self.state.writeHeaderValue("Host", tunnelHost);
        if (self.userAgent) |userAgent|
            try self.state.writeHeaderValue("User-Agent", userAgent)
        else
            try self.state.writeHeaderValue("User-Agent", root.ZeldaDefaultUserAgent);

        // write headers now that we are connected
        if (request.headers) |headerMap| {
            var headerMapIter = headerMap.iterator();
            while (headerMapIter.next()) |kv| {
                var value = try kv.value_ptr.value(self.allocator);
                defer self.allocator.free(value);

                try self.state.writeHeaderValue(kv.key_ptr.*, value);
            }
        }

        // write body
        if (request.body) |body| {
            switch (body.kind) {
                .JSON => try self.state.writeHeaderValue("Content-Type", "application/json"),
                .URLEncodedForm => try self.state.writeHeaderValue("Content-Type", "application/x-www-form-urlencoded"),
                else => {},
            }
            var contentLengthBuffer: [64]u8 = undefined;
            const contentLength = try std.fmt.bufPrint(&contentLengthBuffer, "{}", .{body.bytes.len});
            try self.state.writeHeaderValue("Content-Length", contentLength);
            try self.state.finishHeaders();
            try self.state.writePayload(body.bytes);
        } else {
            try self.state.finishHeaders();
            try self.state.writePayload(null);
        }
        root.logger.debug("Finished sending request...", .{});

        var event = try self.state.next();
        if (event == null or event.? != .status) {
            return error.MissingStatus;
        }
        const rawCode = try std.math.cast(u10, event.?.status.code);
        const responseCode = @intToEnum(hzzp.StatusCode, rawCode);

        // read response headers
        var response = Response.init(self.allocator, responseCode);

        event = try self.state.next();

        while (event != null and event.? != .head_done) : (event = try self.state.next()) {
            switch (event.?) {
                .header => |header| {
                    const value = try self.allocator.alloc(u8, header.value.len);
                    std.mem.copy(u8, value, header.value);

                    if (response.headers.getEntry(header.name)) |entry| {
                        try entry.value_ptr.parts.append(value);
                    } else {
                        var list = req.HeaderValue.init(self.allocator);
                        try list.parts.append(value);

                        const name = try self.allocator.alloc(u8, header.name.len);
                        std.mem.copy(u8, name, header.name);

                        try response.headers.put(name, list);
                    }
                },
                else => return error.ExpectedHeaders,
            }
        }

        // read response body (if any)
        var bodyReader = self.state.payloadReader();
        response.body = switch (bodyReader) {
            .SSLReader => |reader| try reader.readAllAlloc(self.allocator, std.math.maxInt(u64)),
            .Reader => |reader| try reader.readAllAlloc(self.allocator, std.math.maxInt(u64)),
        };

        // finish

        return response;
    }
};
