const std = @import("std");
const zelda = @import("zelda");

const out = std.log.scoped(.connection_pooling);

const TestCount = 8;

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();

    const url = "https://google.com";
    const noPoolAvg = try testConnection(&arena.allocator, url, false);
    const poolAvg = try testConnection(&arena.allocator, url, true);

    out.info("pooling saved an avg of {}", .{std.fmt.fmtDuration(noPoolAvg - poolAvg)});
}

fn testConnection(allocator: *std.mem.Allocator, url: []const u8, use_conn_pool: bool) anyerror!u64 {
    var times = std.ArrayList(u64).init(allocator);
    defer times.deinit();

    var count: usize = 0;
    var timer = try std.time.Timer.start();
    while (count < TestCount) : (count += 1) {
        timer.reset();
        var client = try zelda.Client.init(allocator, .{});
        defer client.deinit();

        var request = zelda.request.Request{ .method = .GET, .url = url, .use_global_connection_pool = use_conn_pool };

        _ = try client.perform(request);

        const requestDuration = timer.lap();
        try times.append(requestDuration);
        out.info("[{}] request took {}", .{ count + 1, std.fmt.fmtDuration(requestDuration) });
    }

    var sum: u64 = 0;
    for (times.items) |time|
        sum += time;
    const avg = sum / times.items.len;
    out.info("pool={}, Avg {}", .{ use_conn_pool, std.fmt.fmtDuration(avg) });
    return avg;
}
