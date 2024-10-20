const std = @import("std");
const c = @cImport({
    @cInclude("regex.h");
});

const sqlite = @import("sqlite");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len < 3) {
        return error.IncorrectArgs;
    }

    if (!std.mem.eql(u8, args[1], "-p")) {
        return error.IncorrectArgs;
    }

    const db = try sqlite.Database.open(.{ .path = "./firewall.db", .create = true });
    defer db.close();

    try createTables(db);

    const port: ?u16 = try std.fmt.parseInt(u16, args[2], 10);

    if (port) |unport| {
        try listen(unport, gpa, db);
    }
}

fn createTables(db: sqlite.Database) !void {
    const portTable =
        \\CREATE TABLE IF NOT EXISTS port_count (
        \\ID integer primary key,
        \\Port integer not null unique,
        \\Count integer not null)
    ;
    try db.exec(portTable, .{});

    const ipTable =
        \\CREATE TABLE IF NOT EXISTS ip_count (
        \\ID integer primary key,
        \\Ip text not null unique,
        \\Count integer not null)
    ;

    try db.exec(ipTable, .{});
}

fn listen(port: u16, gpa: std.mem.Allocator, db: sqlite.Database) !void {
    const file = try std.fs.cwd().createFile(
        "./firewall-log.txt",
        .{ .read = true },
    );
    defer file.close();

    const initString = "Listening on port: ";

    const portStr = try std.fmt.allocPrint(gpa, "{}\n", .{port});
    const fullStr = try std.mem.concat(gpa, u8, &[_][]const u8{ initString, portStr });
    try file.writeAll(fullStr);

    const address = try std.net.Address.parseIp4("0.0.0.0", port);
    const socket = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);

    defer std.posix.close(socket);

    try std.posix.bind(socket, &address.any, address.getOsSockLen());
    var buf: [400]u8 = undefined;
    std.log.info("Bound to port \n", .{});

    var otherAddr: std.posix.sockaddr = undefined;
    var otherAddrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

    var fireWallPattern: c.regex_t = undefined;

    const pattern = "SRC=([0-9.]+) DST=([0-9.]+) LEN=([0-9]+) TOS=([a-zA-Z0-9]+) PREC=([a-zA-Z0-9]+) TTL=([0-9]+) ID=([0-9]+) PROTO=([a-zA-Z0-9]+) SPT=([0-9]+) DPT=([0-9]+) SEQ=([0-9]+) ACK=([0-9]+) WINDOW=([0-9]+) RES=([a-zA-Z0-9]+) ([a-zA-Z0-9]+) URGP=([0-9]+)";

    if (c.regcomp(&fireWallPattern, pattern, c.REG_NEWLINE | c.REG_EXTENDED) != 0) {
        std.log.err("Failed to compile regex for firewall pattern matching", .{});
        return error.FailedToCompRegex;
    }

    const portPattern = struct { port: i32, count: i32 };
    const ipPattern = struct { ip: sqlite.Text, count: i32 };
    const countPattern = struct { Count: ?i32 };

    const countIpSelect = try db.prepare(struct { ip: sqlite.Text }, countPattern, "SELECT Count FROM ip_count WHERE Ip = :ip");
    defer countIpSelect.finalize();

    const countPortSelect = try db.prepare(struct { port: i32 }, countPattern, "SELECT Count FROM port_count WHERE Port = :port");
    defer countPortSelect.finalize();

    const ipInstert = try db.prepare(ipPattern, void, "INSERT INTO ip_count VALUES (NULL, :ip, :count)");

    defer ipInstert.finalize();

    const portInstert = try db.prepare(portPattern, void, "INSERT INTO port_count VALUES (NULL, :port, :count)");

    defer portInstert.finalize();

    const ipUpdate = try db.prepare(ipPattern, void, "UPDATE ip_count SET Count = :count WHERE Ip = :ip");

    defer ipUpdate.finalize();

    const portUpdate = try db.prepare(portPattern, void, "UPDATE port_count SET Count = :count WHERE Port = :port");

    defer portUpdate.finalize();

    while (true) {
        const n_rec = try std.posix.recvfrom(socket, buf[0..], 0, &otherAddr, &otherAddrlen);
        var matches: [17]c.regmatch_t = undefined;
        const log = buf[0..n_rec];
        try file.writeAll(log);

        if (0 == c.regexec(&fireWallPattern, @ptrCast(log), matches.len, &matches, 0)) {
            std.log.info("Blocked request\n {s}", .{buf[0..n_rec]});

            const srcIp = log[@as(usize, @intCast(matches[1].rm_so))..@as(usize, @intCast(matches[1].rm_eo))];
            const desPort = try std.fmt.parseInt(i32, log[@as(usize, @intCast(matches[10].rm_so))..@as(usize, @intCast(matches[10].rm_eo))], 10);

            try countIpSelect.bind(.{ .ip = sqlite.text(srcIp) });
            defer countIpSelect.reset();

            if (try countIpSelect.step()) |count| {
                std.log.info("This ip has been seen {d}", .{count.Count orelse 0});
                if (count.Count) |*newCount| {
                    try ipUpdate.exec(.{ .ip = sqlite.text(srcIp), .count = newCount.* + 1 });
                }
            } else {
                try ipInstert.exec(.{ .ip = sqlite.text(srcIp), .count = 1 });
            }

            try countPortSelect.bind(.{ .port = desPort });
            defer countPortSelect.reset();

            if (try countPortSelect.step()) |count| {
                std.log.info("This port has been seen {d}", .{count.Count orelse 0});
                if (count.Count) |*newCount| {
                    try portUpdate.exec(.{ .port = desPort, .count = newCount.* + 1 });
                }
            } else {
                try portInstert.exec(.{ .port = desPort, .count = 1 });
            }
        }
    }
}
