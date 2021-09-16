pub const zuri = @import("zuri");
pub const hzzp = @import("hzzp");
pub const libressl = @import("zig-libressl");

pub const ZeldaDefaultUserAgent = "zelda/0.0.1";

pub const logger = @import("std").log.scoped(.zelda);
pub const request = @import("request.zig");
pub const client = @import("client.zig");
pub const HttpClient = client.Client;

pub usingnamespace @import("oneshot.zig");

pub fn cleanup() void {
    client.globalConnectionCache.deinit();
}
