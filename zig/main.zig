const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Random = std.rand.Random;

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Sha512 = std.crypto.hash.sha2.Sha512;

const KeyPair = Ed25519.KeyPair;
const PublicKey = Ed25519.PublicKey;
const SecretKey = Ed25519.SecretKey;
const Signature = Ed25519.Signature;
const Verifier = Ed25519.Verifier;
const Curve = Ed25519.Curve;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa.allocator();
    var rng = std.rand.DefaultPrng.init(4349);
    const random = rng.random();

    try benchmarkRandomSignatures(gpa_allocator, random, 1_000);
    try benchmarkMul(random, 1_000);
    try benchmarkArrayEquality(gpa_allocator, random, 100_000_000);
}

fn benchmarkMul(
    random: Random,
    num_iter: usize,
) !void {
    // generate scalars
    var scalar1: [32]u8 = undefined;
    var scalar2: [32]u8 = undefined;
    random.bytes(&scalar1);
    random.bytes(&scalar2);

    // generate curve point
    var seed: [KeyPair.seed_length]u8 = undefined;
    random.bytes(&seed);
    const key = try KeyPair.create(seed);
    var edwards = try Edwards25519.fromBytes(key.public_key.bytes);

    // recursively multiply
    var timer = try std.time.Timer.start();
    for (0..num_iter) |_| {
        edwards = try Curve.basePoint.mulDoubleBasePublic(scalar1, edwards, scalar2);
    }
    std.debug.print("muls: {} ms\n", .{timer.lap() / std.time.ns_per_ms});
}

fn benchmarkArrayEquality(
    allocator: Allocator,
    random: Random,
    num_bytes: usize,
) !void {
    const one = try allocator.alloc(u8, num_bytes);
    const two = try allocator.alloc(u8, num_bytes);

    var timer = try std.time.Timer.start();
    random.bytes(one);
    random.bytes(two);
    std.debug.print("generate arrays: {} ms\n", .{timer.lap() / std.time.ns_per_ms});

    var c: usize = 0;
    for (0..num_bytes) |i| {
        if (one[i] == two[i]) {
            c += 1;
        }
    }
    std.debug.print(
        "compare arrays: {} ms ({})\n",
        .{ timer.lap() / std.time.ns_per_ms, num_bytes / c },
    );
}

/// - randomly generates keys and payload
/// - signs payload with each key
/// - verifies each signature
fn benchmarkRandomSignatures(
    allocator: Allocator,
    random: Random,
    num_keys: usize,
) !void {
    var data_to_sign: [1200]u8 = undefined;
    random.bytes(&data_to_sign);

    var keys = try ArrayList(KeyPair).initCapacity(allocator, num_keys);
    var timer = try std.time.Timer.start();
    for (0..num_keys) |_| {
        var seed: [KeyPair.seed_length]u8 = undefined;
        random.bytes(&seed);
        keys.appendAssumeCapacity(try KeyPair.create(seed));
    }
    std.debug.print("generate keys: {} ms\n", .{timer.lap() / std.time.ns_per_ms});

    var signatures = try ArrayList(Signature).initCapacity(allocator, num_keys);
    _ = timer.lap();
    for (keys.items) |*key| {
        const signature = try key.sign(&data_to_sign, null);
        signatures.appendAssumeCapacity(signature);
    }
    std.debug.print("sign: {} ms\n", .{timer.lap() / std.time.ns_per_ms});

    _ = timer.lap();
    for (0..num_keys) |i| {
        const signature = signatures.items[i];
        const keypair = &keys.items[i];
        try verify(signature, &data_to_sign, keypair.public_key);
    }
    std.debug.print("verify: {} ms\n", .{timer.lap() / std.time.ns_per_ms});
}

pub fn verify(self: Signature, msg: []const u8, public_key: PublicKey) !void {
    var st = try self.verifier(public_key);
    st.update(msg);
    return verifyWith(&st);
}

/// Verify that the signature is valid for the entire message.
pub fn verifyWith(self: *Verifier) !void {
    var hram64: [Sha512.digest_length]u8 = undefined;
    self.h.final(&hram64);
    const hram = Curve.scalar.reduce64(hram64);

    const sb_ah = try mulDoubleBasePublic(Curve.basePoint, self.s, self.a.neg(), hram);
    if (self.expected_r.sub(sb_ah).rejectLowOrder()) {
        return error.SignatureVerificationFailed;
    } else |_| {}
}

/// Double-base multiplication of public parameters - Compute (p1*s1)+(p2*s2) *IN VARIABLE TIME*
/// This can be used for signature verification.
pub fn mulDoubleBasePublic(p1: Edwards25519, s1: [32]u8, p2: Edwards25519, s2: [32]u8) !Edwards25519 {
    var pc1_array: [9]Edwards25519 = undefined;
    const pc1 = if (p1.is_base) basePointPc[0..9] else pc: {
        pc1_array = precompute(p1, 8);
        pc1_array[4].rejectIdentity() catch return error.WeakPublicKey;
        break :pc &pc1_array;
    };
    var pc2_array: [9]Edwards25519 = undefined;
    const pc2 = if (p2.is_base) basePointPc[0..9] else pc: {
        pc2_array = precompute(p2, 8);
        pc2_array[4].rejectIdentity() catch return error.WeakPublicKey;
        break :pc &pc2_array;
    };
    const e1 = slide(s1);
    const e2 = slide(s2);
    var q = Edwards25519.identityElement;
    var pos: usize = 2 * 32 - 1;
    while (true) : (pos -= 1) {
        const slot1 = e1[pos];
        if (slot1 > 0) {
            q = q.add(pc1[@as(usize, @intCast(slot1))]);
        } else if (slot1 < 0) {
            q = q.sub(pc1[@as(usize, @intCast(-slot1))]);
        }
        const slot2 = e2[pos];
        if (slot2 > 0) {
            q = q.add(pc2[@as(usize, @intCast(slot2))]);
        } else if (slot2 < 0) {
            q = q.sub(pc2[@as(usize, @intCast(-slot2))]);
        }
        if (pos == 0) break;
        q = q.dbl().dbl().dbl().dbl();
    }
    try q.rejectIdentity();
    return q;
}

const basePointPc = pc: {
    @setEvalBranchQuota(10000);
    break :pc precompute(Edwards25519.basePoint, 15);
};

fn precompute(p: Edwards25519, comptime count: usize) [1 + count]Edwards25519 {
    var pc: [1 + count]Edwards25519 = undefined;
    pc[0] = Edwards25519.identityElement;
    pc[1] = p;
    var i: usize = 2;
    while (i <= count) : (i += 1) {
        pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
    }
    return pc;
}

fn slide(s: [32]u8) [2 * 32]i8 {
    const reduced = if ((s[s.len - 1] & 0x80) == 0) s else Curve.scalar.reduce(s);
    var e: [2 * 32]i8 = undefined;
    for (reduced, 0..) |x, i| {
        e[i * 2 + 0] = @as(i8, @as(u4, @truncate(x)));
        e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
    }
    // Now, e[0..63] is between 0 and 15, e[63] is between 0 and 7
    var carry: i8 = 0;
    for (e[0..63]) |*x| {
        x.* += carry;
        carry = (x.* + 8) >> 4;
        x.* -= carry * 16;
    }
    e[63] += carry;
    // Now, e[*] is between -8 and 8, including e[63]
    return e;
}

fn loadKeypairs(allocator: Allocator, path: []const u8) !ArrayList(KeyPair) {
    var list = ArrayList(KeyPair).init(allocator);

    while (true) {
        const file = try std.fs.cwd().openFile(path, .{});
        // try file.seekTo(0); // necessary?
        var buf: [SecretKey.encoded_length]u8 = undefined;
        _ = try file.read(&buf);
        const sk = try SecretKey.fromBytes(buf);
        const kp = try KeyPair.fromSecretKey(sk);
        try list.append(kp);
    }
}
