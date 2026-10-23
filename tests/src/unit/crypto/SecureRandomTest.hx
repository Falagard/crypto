package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.random.SecureRandom;

class SecureRandomTest extends Test {
	public function test_securerandom():Void {
		trace("SecureRandom tests");
		var testFailed:Bool = false;
		var time = Timer.stamp();
		var randomInt = SecureRandom.int();
		if ( randomInt < -2147483648 || randomInt > 2147483647) {
			testFailed = true;
			trace("Secure random Int test failed "+randomInt);
		}
		var randomBytes = SecureRandom.bytes(16);
		if (randomBytes == null || randomBytes.length != 16) {
			testFailed = true;
			trace("Secure random Bytes test failed ");
		}
		var randomFloat = SecureRandom.float();
		if (randomFloat < 0.0 || randomFloat >= 1.0) {
			testFailed = true;
			trace("Secure random Float test failed with "+randomFloat);
		}
		f(testFailed);
		time = Timer.stamp() - time;
		trace("Finished SecureRandom: " + time + " seconds");
	}

	#if sys
	// The Windows source (PowerShell + .NET RandomNumberGenerator) must fail closed: exact length
	// or an exception, never Math.random() and never a zero-padded short buffer. The decode step
	// is checked here on every platform; the PowerShell process itself only runs on Windows.
	public function testWindowsOutputDecodeAcceptsExactLength():Void {
		var src = haxe.io.Bytes.alloc(32);
		for (i in 0...32) src.set(i, (i * 37 + 11) & 0xFF);
		var b64 = haxe.crypto.Base64.encode(src);
		var out = haxe.crypto.random.SecureRandom.decodeWindowsOutput(b64 + "\r\n", 32);
		eq(out.toHex(), src.toHex());
	}

	public function testWindowsOutputDecodeRejectsShortOutput():Void {
		var b64 = haxe.crypto.Base64.encode(haxe.io.Bytes.alloc(16));
		t(throws(() -> haxe.crypto.random.SecureRandom.decodeWindowsOutput(b64, 32)));
	}

	public function testWindowsOutputDecodeRejectsGarbageAndEmpty():Void {
		t(throws(() -> haxe.crypto.random.SecureRandom.decodeWindowsOutput("12,34,not bytes", 4)));
		t(throws(() -> haxe.crypto.random.SecureRandom.decodeWindowsOutput("", 4)));
		t(throws(() -> haxe.crypto.random.SecureRandom.decodeWindowsOutput(null, 4)));
	}

	static function throws(f:() -> Dynamic):Bool {
		try {
			f();
		} catch (e:Dynamic) {
			return true;
		}
		return false;
	}
	#end
}
