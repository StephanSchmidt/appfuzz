// appfuzz language test: the n+1 bug from the Rust bench app `chatty`,
// written in Zig. Lists all items, then fetches each one again.
//
// The component glue is C from `wit-bindgen c` (gen/); the types below
// mirror gen/items_app.h. Memory handed to the host comes from libc
// malloc, because the generated post-return frees it with free().
const std = @import("std");

const Str = extern struct { ptr: ?[*]u8, len: usize };
const Pair = extern struct { f0: Str, f1: Str };
const Pairs = extern struct { ptr: ?[*]Pair, len: usize };
const Item = extern struct { id: u64, name: Str, owner: Str, score: u32 };
const Items = extern struct { ptr: ?[*]Item, len: usize };
const Request = extern struct { method: Str, path: Str, query: Pairs, form: Pairs, today: Str, now: Str };
const Response = extern struct { status: u16, body: Str, headers: Pairs };

extern fn bench_web_items_all(ret: *Items) void;
extern fn bench_web_items_get(id: u64, ret: *Item, err: *Str) bool;
extern fn bench_web_items_list_item_free(ptr: *Items) void;
extern fn bench_web_items_item_free(ptr: *Item) void;
extern fn items_app_string_free(ptr: *Str) void;
extern fn bench_web_types_request_free(ptr: *Request) void;
extern fn malloc(n: usize) ?[*]u8;

fn slice(s: Str) []const u8 {
    return if (s.ptr) |p| p[0..s.len] else "";
}

/// A malloc'd copy, owned by the host after return.
fn owned(s: []const u8) Str {
    const p = malloc(@max(s.len, 1)) orelse @panic("out of memory");
    @memcpy(p[0..s.len], s);
    return .{ .ptr = p, .len = s.len };
}

fn esc(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    for (s) |c| switch (c) {
        '&' => try out.appendSlice(gpa, "&amp;"),
        '<' => try out.appendSlice(gpa, "&lt;"),
        '>' => try out.appendSlice(gpa, "&gt;"),
        '"' => try out.appendSlice(gpa, "&quot;"),
        else => try out.append(gpa, c),
    };
}

fn page(gpa: std.mem.Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(gpa, "<ul>");
    var all: Items = undefined;
    bench_web_items_all(&all);
    defer bench_web_items_list_item_free(&all);
    const items = if (all.ptr) |p| p[0..all.len] else &[_]Item{};
    for (items) |it| {
        var full: Item = undefined;
        var err: Str = undefined;
        if (!bench_web_items_get(it.id, &full, &err)) {
            items_app_string_free(&err);
            continue; // not found: skip
        }
        defer bench_web_items_item_free(&full);
        try out.appendSlice(gpa, "<li>");
        try esc(&out, gpa, slice(full.owner));
        try out.appendSlice(gpa, "</li>");
    }
    try out.appendSlice(gpa, "</ul>");
    return out.toOwnedSlice(gpa);
}

export fn exports_bench_web_handler_handle(req: *Request, ret: *Response) void {
    bench_web_types_request_free(req);
    const gpa = std.heap.c_allocator;
    const body = page(gpa) catch @panic("out of memory");
    defer gpa.free(body);
    const headers = @as([*]Pair, @ptrCast(@alignCast(malloc(@sizeOf(Pair)) orelse @panic("out of memory"))));
    headers[0] = .{ .f0 = owned("content-type"), .f1 = owned("text/html") };
    ret.* = .{ .status = 200, .body = owned(body), .headers = .{ .ptr = headers, .len = 1 } };
}
