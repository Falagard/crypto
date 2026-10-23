package haxe.crypto.random;

import haxe.io.Bytes;

/**
 * Cross-platform cryptographically secure random number generator
 */
class SecureRandom {
	static inline var URANDOM = "/dev/urandom";
	static inline var MAX_UINT32 = 4294967296.0;

	static var initialized = false;

	#if cs
	static var csprng:cs.system.security.cryptography.RandomNumberGenerator;
	#elseif (java || jvm)
	static var srng:java.security.SecureRandom;
	#end

	static function init() {
		#if cs
		csprng = cs.system.security.cryptography.RandomNumberGenerator.Create();
		#elseif (java || jvm)
		srng = new java.security.SecureRandom();
		#end
		initialized = true;
	}

	/**
	 * Returns a secure random 32-bit signed integer.
	 */
	public static function int():Int {
		if (!initialized)
			init();
		#if cs
		var buf = new cs.NativeArray<cs.types.UInt8>(4);
		csprng.GetBytes(buf);
		return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
		#elseif (java || jvm)
		return srng.nextInt();
		#elseif js
		return jsInt();
		#elseif python
		var data = python.Syntax.code("__import__('os').urandom(4)");
		return python.Syntax.code("__import__('struct').unpack('>i', {0})[0]", data);
		#elseif php
		return php.Syntax.code("random_int(-2147483648, 2147483647)");
		#elseif flash
		var buf:Bytes = Bytes.ofData(untyped __global__["flash.crypto.generateRandomBytes"](4));
		return (buf.get(0) << 24) | (buf.get(1) << 16) | (buf.get(2) << 8) | buf.get(3);
		#elseif (sys || interp || macro)
		return sysInt();
		#end
		throw "Secure random not supported on this target";
	}

	/**
	 * Returns secure random bytes.
	 */
	public static function bytes(length:Int):Bytes {
		if (length <= 0)
			return Bytes.alloc(0);
		if (!initialized)
			init();
		#if cs
		var buf = new cs.NativeArray<cs.types.UInt8>(length);
		csprng.GetBytes(buf);
		var result = Bytes.alloc(length);
		for (i in 0...length)
			result.set(i, buf[i]);
		return result;
		#elseif (java || jvm)
		var result = Bytes.alloc(length);
		srng.nextBytes(cast result.getData());
		return result;
		#elseif js
		return jsBytes(length);
		#elseif python
		var data = python.Syntax.code("__import__('os').urandom({0})", length);
		var result = Bytes.alloc(length);
		for (i in 0...length) {
			result.set(i, python.Syntax.code("{0}[{1}]", data, i));
		}
		return result;
		#elseif php
		return Bytes.ofString(php.Syntax.code("random_bytes({0})", length));
		#elseif flash
		return Bytes.ofData(untyped __global__["flash.crypto.generateRandomBytes"](length));
		#elseif (sys || interp || macro)
		return sysBytes(length);
		#end
		throw "Secure random not supported on this target";
	}

	/**
	 * Returns a random float between 0.0 (inclusive) and 1.0 (exclusive)
	 */
	public static function float():Float {
		var i = int();
		var unsigned:Float = i < 0 ? i + MAX_UINT32 : i;
		return unsigned / MAX_UINT32;
	}

	/**
	 * Returns a random integer within the specified range
	 */
	public static function range(min:Int, max:Int):Int {
		if (min >= max)
			throw "Invalid range: min must be less than max";
		return min + Math.floor(float() * (max - min));
	}

	/**
	 * Returns a random boolean value.
	 */
	public static function bool():Bool {
		return (int() & 1) == 1;
	}

	/**
	 * Fill an existing Bytes object with secure random data
	 * @param dest The Bytes to fill
	 * @param offset Starting offset
	 * @param length Number of bytes to fill (default: entire length)
	 */
	public static function fillBytes(dest:Bytes, offset:Int = 0, length:Int = -1):Void {
		if (length == -1) {
			length = dest.length - offset;
		}
		if (offset < 0 || length < 0 || offset + length > dest.length) {
			throw "Invalid offset or length";
		}
		dest.blit(offset, bytes(length), 0, length);
	}

	/**
	 * Secure random string of specified length with given character set
	 * @param length Length of the string
	 * @param charset Character set to use (default: alphanumeric)
	 * @return Secure random string
	 */
	public static function string(length:Int, charset:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):String {
		var result = new StringBuf();
		var charsetLength = charset.length;
		var randomBytes = bytes(length);
		var rnd:Float = 0;
		for (i in 0...randomBytes.length) {
			var index = Std.int(randomBytes.get(i) * charsetLength / 256);
			result.add(charset.charAt(index));
		}
		return result.toString();
	}

	/**
	 * Secure random hexadecimal string
	 * @param length Number of hex characters to generate
	 * @return Random hex string
	 */
	public static function hex(length:Int):String {
		return string(length, "0123456789ABCDEF");
	}

	#if js
	static function jsInt():Int {
		if (js.Syntax.typeof(js.Syntax.code("globalThis.crypto")) != "undefined") {
			var buf = new js.lib.Int32Array(1);
			js.Syntax.code("globalThis.crypto").getRandomValues(buf);
			return buf[0];
		}
		throw "No secure random source available";
	}

	static function jsBytes(length:Int):Bytes {
		if (js.Syntax.typeof(js.Syntax.code("globalThis.crypto")) != "undefined") {
			var buf = new js.lib.Uint8Array(length);
			js.Syntax.code("globalThis.crypto").getRandomValues(buf);
			var result = Bytes.alloc(length);
			for (i in 0...length)
				result.set(i, buf[i]);
			return result;
		}
		throw "No secure random source available";
	}
	#end

	#if (sys || interp || macro)
	static function sysInt():Int {
		if (sys.FileSystem.exists(URANDOM)) {
			var file = sys.io.File.read(URANDOM);
			var result = file.readInt32();
			file.close();
			return result;
		}
		if (Sys.systemName() == "Windows") {
			return winInt();
		}
		throw "No secure random source available";
	}

	static function sysBytes(length:Int):Bytes {
		if (sys.FileSystem.exists(URANDOM)) {
			var file = sys.io.File.read(URANDOM);
			var result = file.read(length);
			file.close();
			return result;
		}
		if (Sys.systemName() == "Windows") {
			return winBytes(length);
		}
		throw "No secure random source available";
	}

	static function winInt():Int {
		var b = winBytes(4);
		return (b.get(0) << 24) | (b.get(1) << 16) | (b.get(2) << 8) | b.get(3);
	}

	/**
	 * Windows has no /dev/urandom, and this library has no native binding, so bytes come from
	 * .NET's RandomNumberGenerator through PowerShell. Two rules:
	 *
	 * - **Fail closed.** The output must decode to exactly the requested number of bytes, or
	 *   this throws. It never substitutes Math.random() for a value it cannot parse, and never
	 *   returns a buffer whose tail was left as zeros because the output was short.
	 * - **Batch.** Starting PowerShell takes hundreds of milliseconds, so bytes are fetched
	 *   WIN_BATCH_BYTES at a time into a private pool and handed out once each (never reused).
	 *
	 * A native call (BCryptGenRandom) would be better than a child process; this is the fallback
	 * until a binding exists.
	 */
	static inline var WIN_BATCH_BYTES = 4096;

	static var winPool:Null<Bytes> = null;
	static var winPoolPos = 0;
	#if target.threaded
	static var winLock = new sys.thread.Mutex();
	#end

	static function winBytes(length:Int):Bytes {
		#if target.threaded
		winLock.acquire();
		#end
		try {
			var result = Bytes.alloc(length);
			var filled = 0;
			while (filled < length) {
				if (winPool == null || winPoolPos >= winPool.length) {
					winPool = winFetch(length - filled > WIN_BATCH_BYTES ? length - filled : WIN_BATCH_BYTES);
					winPoolPos = 0;
				}
				var take = winPool.length - winPoolPos;
				if (take > length - filled)
					take = length - filled;
				result.blit(filled, winPool, winPoolPos, take);
				// Wipe what was handed out so the pool never holds bytes that left it.
				winPool.fill(winPoolPos, take, 0);
				winPoolPos += take;
				filled += take;
			}
			#if target.threaded
			winLock.release();
			#end
			return result;
		} catch (e:Dynamic) {
			#if target.threaded
			winLock.release();
			#end
			throw e;
		}
	}

	static function winFetch(count:Int):Bytes {
		var output:String = null;
		var code = -1;
		try {
			var proc = new sys.io.Process("powershell", [
				"-NoProfile",
				"-NonInteractive",
				"-Command",
				"$r=[System.Security.Cryptography.RandomNumberGenerator]::Create();"
				+ "$b=New-Object byte[] " + count + ";$r.GetBytes($b);$r.Dispose();[Convert]::ToBase64String($b)"
			]);
			output = proc.stdout.readAll().toString();
			code = proc.exitCode();
			proc.close();
		} catch (e:Dynamic) {
			throw "No secure random source available: " + e;
		}
		if (code != 0)
			throw "No secure random source available: PowerShell exited with " + code;
		return decodeWindowsOutput(output, count);
	}

	/**
	 * Decodes PowerShell's base64 output and checks it is exactly `expected` bytes; throws
	 * otherwise. Separate so it can be tested on any platform.
	 */
	public static function decodeWindowsOutput(output:Null<String>, expected:Int):Bytes {
		if (output == null)
			throw "No secure random source available: no output";
		var text = StringTools.trim(output);
		var decoded:Bytes = null;
		try {
			decoded = haxe.crypto.Base64.decode(text);
		} catch (e:Dynamic) {
			throw "No secure random source available: output is not base64";
		}
		if (decoded == null || decoded.length != expected)
			throw "No secure random source available: expected " + expected + " bytes, got "
				+ (decoded == null ? 0 : decoded.length);
		return decoded;
	}
	#end
}
