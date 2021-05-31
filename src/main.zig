pub const zuri = @import("zuri");
pub const hzzp = @import("hzzp");
pub const iguanaTLS = @import("iguanaTLS");

pub const ZeldaDefaultUserAgent = "zelda/0.0.1";

pub const logger = @import("std").log.scoped(.zelda);
pub const request = @import("request.zig");
pub const Client = @import("client.zig").Client;

pub usingnamespace @import("oneshot.zig");
