if(document.__redditrust_active) {
	updateUIFull();
	ladder(stepladder);
}
document.__redditrust_active = true;

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-512, as defined
 * in FIPS 180-2
 * Version 2.2 Copyright Anonymous Contributor, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */
var hexcase = 0;	
var b64pad	= ""; 

function hex_sha512(s)		{ return rstr2hex(rstr_sha512(str2rstr_utf8(s))); }
function b64_sha512(s)		{ return rstr2b64(rstr_sha512(str2rstr_utf8(s))); }
function any_sha512(s, e) { return rstr2any(rstr_sha512(str2rstr_utf8(s)), e);}
function hex_hmac_sha512(k, d)
	{ return rstr2hex(rstr_hmac_sha512(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_sha512(k, d)
	{ return rstr2b64(rstr_hmac_sha512(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_sha512(k, d, e)
	{ return rstr2any(rstr_hmac_sha512(str2rstr_utf8(k), str2rstr_utf8(d)), e);}

function sha512_vm_test()
{
	return hex_sha512("abc").toLowerCase() ==
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
}

/*
 * Calculate the SHA-512 of a raw string
 */
function rstr_sha512(s)
{
	return binb2rstr(binb_sha512(rstr2binb(s), s.length * 8));
}

/*
 * Calculate the HMAC-SHA-512 of a key and some data (raw strings)
 */
function rstr_hmac_sha512(key, data)
{
	var bkey = rstr2binb(key);
	if(bkey.length > 32) bkey = binb_sha512(bkey, key.length * 8);

	var ipad = Array(32), opad = Array(32);
	for(var i = 0; i < 32; i++)
	{
		ipad[i] = bkey[i] ^ 0x36363636;
		opad[i] = bkey[i] ^ 0x5C5C5C5C;
	}

	var hash = binb_sha512(ipad.concat(rstr2binb(data)), 1024 + data.length * 8);
	return binb2rstr(binb_sha512(opad.concat(hash), 1024 + 512));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
	try { hexcase } catch(e) { hexcase=0; }
	var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
	var output = "";
	var x;
	for(var i = 0; i < input.length; i++)
	{
		x = input.charCodeAt(i);
		output += hex_tab.charAt((x >>> 4) & 0x0F)
					 +	hex_tab.charAt( x				& 0x0F);
	}
	return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
	try { b64pad } catch(e) { b64pad=''; }
	var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	var output = "";
	var len = input.length;
	for(var i = 0; i < len; i += 3)
	{
		var triplet = (input.charCodeAt(i) << 16)
								| (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
								| (i + 2 < len ? input.charCodeAt(i+2)			: 0);
		for(var j = 0; j < 4; j++)
		{
			if(i * 8 + j * 6 > input.length * 8) output += b64pad;
			else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
		}
	}
	return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
	var divisor = encoding.length;
	var i, j, q, x, quotient;

	
	var dividend = Array(Math.ceil(input.length / 2));
	for(i = 0; i < dividend.length; i++)
	{
		dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
	}

	/*
	 * Repeatedly perform a long division. The binary array forms the dividend,
	 * the length of the encoding is the divisor. Once computed, the quotient
	 * forms the dividend for the next step. All remainders are stored for later
	 * use.
	 */
	var full_length = Math.ceil(input.length * 8 /
																		(Math.log(encoding.length) / Math.log(2)));
	var remainders = Array(full_length);
	for(j = 0; j < full_length; j++)
	{
		quotient = Array();
		x = 0;
		for(i = 0; i < dividend.length; i++)
		{
			x = (x << 16) + dividend[i];
			q = Math.floor(x / divisor);
			x -= q * divisor;
			if(quotient.length > 0 || q > 0)
				quotient[quotient.length] = q;
		}
		remainders[j] = x;
		dividend = quotient;
	}

	
	var output = "";
	for(i = remainders.length - 1; i >= 0; i--)
		output += encoding.charAt(remainders[i]);

	return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
	var output = "";
	var i = -1;
	var x, y;

	while(++i < input.length)
	{
		
		x = input.charCodeAt(i);
		y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
		if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
		{
			x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
			i++;
		}

		
		if(x <= 0x7F)
			output += String.fromCharCode(x);
		else if(x <= 0x7FF)
			output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
																		0x80 | ( x				 & 0x3F));
		else if(x <= 0xFFFF)
			output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
																		0x80 | ((x >>> 6 ) & 0x3F),
																		0x80 | ( x				 & 0x3F));
		else if(x <= 0x1FFFFF)
			output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
																		0x80 | ((x >>> 12) & 0x3F),
																		0x80 | ((x >>> 6 ) & 0x3F),
																		0x80 | ( x				 & 0x3F));
	}
	return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
	var output = "";
	for(var i = 0; i < input.length; i++)
		output += String.fromCharCode( input.charCodeAt(i)				& 0xFF,
																	(input.charCodeAt(i) >>> 8) & 0xFF);
	return output;
}

function str2rstr_utf16be(input)
{
	var output = "";
	for(var i = 0; i < input.length; i++)
		output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
																	 input.charCodeAt(i)				& 0xFF);
	return output;
}

/*
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binb(input)
{
	var output = Array(input.length >> 2);
	for(var i = 0; i < output.length; i++)
		output[i] = 0;
	for(var i = 0; i < input.length * 8; i += 8)
		output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
	return output;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2rstr(input)
{
	var output = "";
	for(var i = 0; i < input.length * 32; i += 8)
		output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
	return output;
}

/*
 * Calculate the SHA-512 of an array of big-endian dwords, and a bit length
 */
var sha512_k;
function binb_sha512(x, len)
{
	if(sha512_k == undefined)
	{
				sha512_k = new Array(
new int64(0x428a2f98, -685199838), new int64(0x71374491, 0x23ef65cd),
new int64(-1245643825, -330482897), new int64(-373957723, -2121671748),
new int64(0x3956c25b, -213338824), new int64(0x59f111f1, -1241133031),
new int64(-1841331548, -1357295717), new int64(-1424204075, -630357736),
new int64(-670586216, -1560083902), new int64(0x12835b01, 0x45706fbe),
new int64(0x243185be, 0x4ee4b28c), new int64(0x550c7dc3, -704662302),
new int64(0x72be5d74, -226784913), new int64(-2132889090, 0x3b1696b1),
new int64(-1680079193, 0x25c71235), new int64(-1046744716, -815192428),
new int64(-459576895, -1628353838), new int64(-272742522, 0x384f25e3),
new int64(0xfc19dc6, -1953704523), new int64(0x240ca1cc, 0x77ac9c65),
new int64(0x2de92c6f, 0x592b0275), new int64(0x4a7484aa, 0x6ea6e483),
new int64(0x5cb0a9dc, -1119749164), new int64(0x76f988da, -2096016459),
new int64(-1740746414, -295247957), new int64(-1473132947, 0x2db43210),
new int64(-1341970488, -1728372417), new int64(-1084653625, -1091629340),
new int64(-958395405, 0x3da88fc2), new int64(-710438585, -1828018395),
new int64(0x6ca6351, -536640913), new int64(0x14292967, 0xa0e6e70),
new int64(0x27b70a85, 0x46d22ffc), new int64(0x2e1b2138, 0x5c26c926),
new int64(0x4d2c6dfc, 0x5ac42aed), new int64(0x53380d13, -1651133473),
new int64(0x650a7354, -1951439906), new int64(0x766a0abb, 0x3c77b2a8),
new int64(-2117940946, 0x47edaee6), new int64(-1838011259, 0x1482353b),
new int64(-1564481375, 0x4cf10364), new int64(-1474664885, -1136513023),
new int64(-1035236496, -789014639), new int64(-949202525, 0x654be30),
new int64(-778901479, -688958952), new int64(-694614492, 0x5565a910),
new int64(-200395387, 0x5771202a), new int64(0x106aa070, 0x32bbd1b8),
new int64(0x19a4c116, -1194143544), new int64(0x1e376c08, 0x5141ab53),
new int64(0x2748774c, -544281703), new int64(0x34b0bcb5, -509917016),
new int64(0x391c0cb3, -976659869), new int64(0x4ed8aa4a, -482243893),
new int64(0x5b9cca4f, 0x7763e373), new int64(0x682e6ff3, -692930397),
new int64(0x748f82ee, 0x5defb2fc), new int64(0x78a5636f, 0x43172f60),
new int64(-2067236844, -1578062990), new int64(-1933114872, 0x1a6439ec),
new int64(-1866530822, 0x23631e28), new int64(-1538233109, -561857047),
new int64(-1090935817, -1295615723), new int64(-965641998, -479046869),
new int64(-903397682, -366583396), new int64(-779700025, 0x21c0c207),
new int64(-354779690, -840897762), new int64(-176337025, -294727304),
new int64(0x6f067aa, 0x72176fba), new int64(0xa637dc5, -1563912026),
new int64(0x113f9804, -1090974290), new int64(0x1b710b35, 0x131c471b),
new int64(0x28db77f5, 0x23047d84), new int64(0x32caab7b, 0x40c72493),
new int64(0x3c9ebe0a, 0x15c9bebc), new int64(0x431d67c4, -1676669620),
new int64(0x4cc5d4be, -885112138), new int64(0x597f299c, -60457430),
new int64(0x5fcb6fab, 0x3ad6faec), new int64(0x6c44198c, 0x4a475817));
	}

		var H = new Array(
new int64(0x6a09e667, -205731576),
new int64(-1150833019, -2067093701),
new int64(0x3c6ef372, -23791573),
new int64(-1521486534, 0x5f1d36f1),
new int64(0x510e527f, -1377402159),
new int64(-1694144372, 0x2b3e6c1f),
new int64(0x1f83d9ab, -79577749),
new int64(0x5be0cd19, 0x137e2179));

	var T1 = new int64(0, 0),
		T2 = new int64(0, 0),
		a = new int64(0,0),
		b = new int64(0,0),
		c = new int64(0,0),
		d = new int64(0,0),
		e = new int64(0,0),
		f = new int64(0,0),
		g = new int64(0,0),
		h = new int64(0,0),
				s0 = new int64(0, 0),
		s1 = new int64(0, 0),
		Ch = new int64(0, 0),
		Maj = new int64(0, 0),
		r1 = new int64(0, 0),
		r2 = new int64(0, 0),
		r3 = new int64(0, 0);
	var j, i;
	var W = new Array(80);
	for(i=0; i<80; i++)
		W[i] = new int64(0, 0);

		x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
	x[((len + 128 >> 10)<< 5) + 31] = len;

	for(i = 0; i<x.length; i+=32)	 {
		int64copy(a, H[0]);
		int64copy(b, H[1]);
		int64copy(c, H[2]);
		int64copy(d, H[3]);
		int64copy(e, H[4]);
		int64copy(f, H[5]);
		int64copy(g, H[6]);
		int64copy(h, H[7]);

		for(j=0; j<16; j++)
		{
				W[j].h = x[i + 2*j];
				W[j].l = x[i + 2*j + 1];
		}

		for(j=16; j<80; j++)
		{
						int64rrot(r1, W[j-2], 19);
			int64revrrot(r2, W[j-2], 29);
			int64shr(r3, W[j-2], 6);
			s1.l = r1.l ^ r2.l ^ r3.l;
			s1.h = r1.h ^ r2.h ^ r3.h;
						int64rrot(r1, W[j-15], 1);
			int64rrot(r2, W[j-15], 8);
			int64shr(r3, W[j-15], 7);
			s0.l = r1.l ^ r2.l ^ r3.l;
			s0.h = r1.h ^ r2.h ^ r3.h;

			int64add4(W[j], s1, W[j-7], s0, W[j-16]);
		}

		for(j = 0; j < 80; j++)
		{
						Ch.l = (e.l & f.l) ^ (~e.l & g.l);
			Ch.h = (e.h & f.h) ^ (~e.h & g.h);

						int64rrot(r1, e, 14);
			int64rrot(r2, e, 18);
			int64revrrot(r3, e, 9);
			s1.l = r1.l ^ r2.l ^ r3.l;
			s1.h = r1.h ^ r2.h ^ r3.h;

						int64rrot(r1, a, 28);
			int64revrrot(r2, a, 2);
			int64revrrot(r3, a, 7);
			s0.l = r1.l ^ r2.l ^ r3.l;
			s0.h = r1.h ^ r2.h ^ r3.h;

						Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
			Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

			int64add5(T1, h, s1, Ch, sha512_k[j], W[j]);
			int64add(T2, s0, Maj);

			int64copy(h, g);
			int64copy(g, f);
			int64copy(f, e);
			int64add(e, d, T1);
			int64copy(d, c);
			int64copy(c, b);
			int64copy(b, a);
			int64add(a, T1, T2);
		}
		int64add(H[0], H[0], a);
		int64add(H[1], H[1], b);
		int64add(H[2], H[2], c);
		int64add(H[3], H[3], d);
		int64add(H[4], H[4], e);
		int64add(H[5], H[5], f);
		int64add(H[6], H[6], g);
		int64add(H[7], H[7], h);
	}

		var hash = new Array(16);
	for(i=0; i<8; i++)
	{
		hash[2*i] = H[i].h;
		hash[2*i + 1] = H[i].l;
	}
	return hash;
}

function int64(h, l)
{
	this.h = h;
	this.l = l;
	}

function int64copy(dst, src)
{
	dst.h = src.h;
	dst.l = src.l;
}

function int64rrot(dst, x, shift)
{
		dst.l = (x.l >>> shift) | (x.h << (32-shift));
		dst.h = (x.h >>> shift) | (x.l << (32-shift));
}

function int64revrrot(dst, x, shift)
{
		dst.l = (x.h >>> shift) | (x.l << (32-shift));
		dst.h = (x.l >>> shift) | (x.h << (32-shift));
}

function int64shr(dst, x, shift)
{
		dst.l = (x.l >>> shift) | (x.h << (32-shift));
		dst.h = (x.h >>> shift);
}

function int64add(dst, x, y)
{
	 var w0 = (x.l & 0xffff) + (y.l & 0xffff);
	 var w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
	 var w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
	 var w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
	 dst.l = (w0 & 0xffff) | (w1 << 16);
	 dst.h = (w2 & 0xffff) | (w3 << 16);
}

function int64add4(dst, a, b, c, d)
{
	 var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
	 var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
	 var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
	 var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
	 dst.l = (w0 & 0xffff) | (w1 << 16);
	 dst.h = (w2 & 0xffff) | (w3 << 16);
}

function int64add5(dst, a, b, c, d, e)
{
	 var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff);
	 var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16);
	 var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16);
	 var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
	 dst.l = (w0 & 0xffff) | (w1 << 16);
	 dst.h = (w2 & 0xffff) | (w3 << 16);
}

/*
 * Libraries and License:
 *
 * Copyright (c) 2003-2005	Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.	
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer
 */
var dbits;
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);
function BigInteger(a,b,c) {
	if(a != null)
		if("number" == typeof a) this.fromNumber(a,b,c);
		else if(b == null && "string" != typeof a) this.fromString(a,256);
		else this.fromString(a,b);
}
function nbi() { return new BigInteger(null); }
function am1(i,x,w,j,c,n) {
	while(--n >= 0) {
		var v = x*this[i++]+w[j]+c;
		c = Math.floor(v/0x4000000);
		w[j++] = v&0x3ffffff;
	}
	return c;
}
function am2(i,x,w,j,c,n) {
	var xl = x&0x7fff, xh = x>>15;
	while(--n >= 0) {
		var l = this[i]&0x7fff;
		var h = this[i++]>>15;
		var m = xh*l+h*xl;
		l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
		c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
		w[j++] = l&0x3fffffff;
	}
	return c;
}
function am3(i,x,w,j,c,n) {
	var xl = x&0x3fff, xh = x>>14;
	while(--n >= 0) {
		var l = this[i]&0x3fff;
		var h = this[i++]>>14;
		var m = xh*l+h*xl;
		l = xl*l+((m&0x3fff)<<14)+w[j]+c;
		c = (l>>28)+(m>>14)+xh*h;
		w[j++] = l&0xfffffff;
	}
	return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
	BigInteger.prototype.am = am2;
	dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
	BigInteger.prototype.am = am1;
	dbits = 26;
}
else {	 BigInteger.prototype.am = am3;
	dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
	var c = BI_RC[s.charCodeAt(i)];
	return (c==null)?-1:c;
}

function bnpCopyTo(r) {
	for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
	r.t = this.t;
	r.s = this.s;
}

function bnpFromInt(x) {
	this.t = 1;
	this.s = (x<0)?-1:0;
	if(x > 0) this[0] = x;
	else if(x < -1) this[0] = x+this.DV;
	else this.t = 0;
}

function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

function bnpFromString(s,b) {
	var k;
	if(b == 16) k = 4;
	else if(b == 8) k = 3;
	else if(b == 256) k = 8;	 else if(b == 2) k = 1;
	else if(b == 32) k = 5;
	else if(b == 4) k = 2;
	else { this.fromRadix(s,b); return; }
	this.t = 0;
	this.s = 0;
	var i = s.length, mi = false, sh = 0;
	while(--i >= 0) {
		var x = (k==8)?s[i]&0xff:intAt(s,i);
		if(x < 0) {
			if(s.charAt(i) == "-") mi = true;
			continue;
		}
		mi = false;
		if(sh == 0)
			this[this.t++] = x;
		else if(sh+k > this.DB) {
			this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
			this[this.t++] = (x>>(this.DB-sh));
		}
		else {
			this[this.t-1] |= x<<sh;
		}
		sh += k;
		if(sh >= this.DB) sh -= this.DB;
	}
	if(k == 8 && (s[0]&0x80) != 0) {
		this.s = -1;
		if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
	}
	this.clamp();
	if(mi) BigInteger.ZERO.subTo(this,this);
}

function bnpClamp() {
	var c = this.s&this.DM;
	while(this.t > 0 && this[this.t-1] == c) --this.t;
}

function bnToString(b) {
	if(this.s < 0) return "-"+this.negate().toString(b);
	var k;
	if(b == 16) k = 4;
	else if(b == 8) k = 3;
	else if(b == 2) k = 1;
	else if(b == 32) k = 5;
	else if(b == 4) k = 2;
	else return this.toRadix(b);
	var km = (1<<k)-1, d, m = false, r = "", i = this.t;
	var p = this.DB-(i*this.DB)%k;
	if(i-- > 0) {
		if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
		while(i >= 0) {
			if(p < k) {
				d = (this[i]&((1<<p)-1))<<(k-p);
				d |= this[--i]>>(p+=this.DB-k);
			}
			else {
				d = (this[i]>>(p-=k))&km;
				if(p <= 0) { p += this.DB; --i; }
			}
			if(d > 0) m = true;
			if(m) r += int2char(d);
		}
	}
	return m?r:"0";
}

function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

function bnAbs() { return (this.s<0)?this.negate():this; }

function bnCompareTo(a) {
	var r = this.s-a.s;
	if(r != 0) return r;
	var i = this.t;
	r = i-a.t;
	if(r != 0) return (this.s<0)?-r:r;
	while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
	return 0;
}

function nbits(x) {
	var r = 1, t;
	if((t=x>>>16) != 0) { x = t; r += 16; }
	if((t=x>>8) != 0) { x = t; r += 8; }
	if((t=x>>4) != 0) { x = t; r += 4; }
	if((t=x>>2) != 0) { x = t; r += 2; }
	if((t=x>>1) != 0) { x = t; r += 1; }
	return r;
}

function bnBitLength() {
	if(this.t <= 0) return 0;
	return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

function bnpDLShiftTo(n,r) {
	var i;
	for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
	for(i = n-1; i >= 0; --i) r[i] = 0;
	r.t = this.t+n;
	r.s = this.s;
}

function bnpDRShiftTo(n,r) {
	for(var i = n; i < this.t; ++i) r[i-n] = this[i];
	r.t = Math.max(this.t-n,0);
	r.s = this.s;
}

function bnpLShiftTo(n,r) {
	var bs = n%this.DB;
	var cbs = this.DB-bs;
	var bm = (1<<cbs)-1;
	var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
	for(i = this.t-1; i >= 0; --i) {
		r[i+ds+1] = (this[i]>>cbs)|c;
		c = (this[i]&bm)<<bs;
	}
	for(i = ds-1; i >= 0; --i) r[i] = 0;
	r[ds] = c;
	r.t = this.t+ds+1;
	r.s = this.s;
	r.clamp();
}

function bnpRShiftTo(n,r) {
	r.s = this.s;
	var ds = Math.floor(n/this.DB);
	if(ds >= this.t) { r.t = 0; return; }
	var bs = n%this.DB;
	var cbs = this.DB-bs;
	var bm = (1<<bs)-1;
	r[0] = this[ds]>>bs;
	for(var i = ds+1; i < this.t; ++i) {
		r[i-ds-1] |= (this[i]&bm)<<cbs;
		r[i-ds] = this[i]>>bs;
	}
	if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
	r.t = this.t-ds;
	r.clamp();
}

function bnpSubTo(a,r) {
	var i = 0, c = 0, m = Math.min(a.t,this.t);
	while(i < m) {
		c += this[i]-a[i];
		r[i++] = c&this.DM;
		c >>= this.DB;
	}
	if(a.t < this.t) {
		c -= a.s;
		while(i < this.t) {
			c += this[i];
			r[i++] = c&this.DM;
			c >>= this.DB;
		}
		c += this.s;
	}
	else {
		c += this.s;
		while(i < a.t) {
			c -= a[i];
			r[i++] = c&this.DM;
			c >>= this.DB;
		}
		c -= a.s;
	}
	r.s = (c<0)?-1:0;
	if(c < -1) r[i++] = this.DV+c;
	else if(c > 0) r[i++] = c;
	r.t = i;
	r.clamp();
}

function bnpMultiplyTo(a,r) {
	var x = this.abs(), y = a.abs();
	var i = x.t;
	r.t = i+y.t;
	while(--i >= 0) r[i] = 0;
	for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
	r.s = 0;
	r.clamp();
	if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

function bnpSquareTo(r) {
	var x = this.abs();
	var i = r.t = 2*x.t;
	while(--i >= 0) r[i] = 0;
	for(i = 0; i < x.t-1; ++i) {
		var c = x.am(i,x[i],r,2*i,0,1);
		if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
			r[i+x.t] -= x.DV;
			r[i+x.t+1] = 1;
		}
	}
	if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
	r.s = 0;
	r.clamp();
}

function bnpDivRemTo(m,q,r) {
	var pm = m.abs();
	if(pm.t <= 0) return;
	var pt = this.abs();
	if(pt.t < pm.t) {
		if(q != null) q.fromInt(0);
		if(r != null) this.copyTo(r);
		return;
	}
	if(r == null) r = nbi();
	var y = nbi(), ts = this.s, ms = m.s;
	var nsh = this.DB-nbits(pm[pm.t-1]);		if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
	else { pm.copyTo(y); pt.copyTo(r); }
	var ys = y.t;
	var y0 = y[ys-1];
	if(y0 == 0) return;
	var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
	var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
	var i = r.t, j = i-ys, t = (q==null)?nbi():q;
	y.dlShiftTo(j,t);
	if(r.compareTo(t) >= 0) {
		r[r.t++] = 1;
		r.subTo(t,r);
	}
	BigInteger.ONE.dlShiftTo(ys,t);
	t.subTo(y,y);		while(y.t < ys) y[y.t++] = 0;
	while(--j >= 0) {
				var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
		if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {				y.dlShiftTo(j,t);
			r.subTo(t,r);
			while(r[i] < --qd) r.subTo(t,r);
		}
	}
	if(q != null) {
		r.drShiftTo(ys,q);
		if(ts != ms) BigInteger.ZERO.subTo(q,q);
	}
	r.t = ys;
	r.clamp();
	if(nsh > 0) r.rShiftTo(nsh,r);		if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

function bnMod(a) {
	var r = nbi();
	this.abs().divRemTo(a,null,r);
	if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
	return r;
}

function Classic(m) { this.m = m; }
function cConvert(x) {
	if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
	else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

function bnpInvDigit() {
	if(this.t < 1) return 0;
	var x = this[0];
	if((x&1) == 0) return 0;
	var y = x&3;			y = (y*(2-(x&0xf)*y))&0xf;		y = (y*(2-(x&0xff)*y))&0xff;		y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;				y = (y*(2-x*y%this.DV))%this.DV;				return (y>0)?this.DV-y:-y;
}

function Montgomery(m) {
	this.m = m;
	this.mp = m.invDigit();
	this.mpl = this.mp&0x7fff;
	this.mph = this.mp>>15;
	this.um = (1<<(m.DB-15))-1;
	this.mt2 = 2*m.t;
}

function montConvert(x) {
	var r = nbi();
	x.abs().dlShiftTo(this.m.t,r);
	r.divRemTo(this.m,null,r);
	if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
	return r;
}

function montRevert(x) {
	var r = nbi();
	x.copyTo(r);
	this.reduce(r);
	return r;
}

function montReduce(x) {
	while(x.t <= this.mt2)			x[x.t++] = 0;
	for(var i = 0; i < this.m.t; ++i) {
				var j = x[i]&0x7fff;
		var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
				j = i+this.m.t;
		x[j] += this.m.am(0,u0,x,i,0,this.m.t);
				while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
	}
	x.clamp();
	x.drShiftTo(this.m.t,x);
	if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

function bnpExp(e,z) {
	if(e > 0xffffffff || e < 1) return BigInteger.ONE;
	var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
	g.copyTo(r);
	while(--i >= 0) {
		z.sqrTo(r,r2);
		if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
		else { var t = r; r = r2; r2 = t; }
	}
	return z.revert(r);
}

function bnModPowInt(e,m) {
	var z;
	if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
	return this.exp(e,z);
}

BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);



function bnClone() { var r = nbi(); this.copyTo(r); return r; }

function bnIntValue() {
	if(this.s < 0) {
		if(this.t == 1) return this[0]-this.DV;
		else if(this.t == 0) return -1;
	}
	else if(this.t == 1) return this[0];
	else if(this.t == 0) return 0;
		return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

function bnSigNum() {
	if(this.s < 0) return -1;
	else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
	else return 1;
}

function bnpToRadix(b) {
	if(b == null) b = 10;
	if(this.signum() == 0 || b < 2 || b > 36) return "0";
	var cs = this.chunkSize(b);
	var a = Math.pow(b,cs);
	var d = nbv(a), y = nbi(), z = nbi(), r = "";
	this.divRemTo(d,y,z);
	while(y.signum() > 0) {
		r = (a+z.intValue()).toString(b).substr(1) + r;
		y.divRemTo(d,y,z);
	}
	return z.intValue().toString(b) + r;
}

function bnpFromRadix(s,b) {
	this.fromInt(0);
	if(b == null) b = 10;
	var cs = this.chunkSize(b);
	var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
	for(var i = 0; i < s.length; ++i) {
		var x = intAt(s,i);
		if(x < 0) {
			if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
			continue;
		}
		w = b*w+x;
		if(++j >= cs) {
			this.dMultiply(d);
			this.dAddOffset(w,0);
			j = 0;
			w = 0;
		}
	}
	if(j > 0) {
		this.dMultiply(Math.pow(b,j));
		this.dAddOffset(w,0);
	}
	if(mi) BigInteger.ZERO.subTo(this,this);
}

function bnpFromNumber(a,b,c) {
	if("number" == typeof b) {
				if(a < 2) this.fromInt(1);
		else {
			this.fromNumber(a,c);
			if(!this.testBit(a-1))					this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
			if(this.isEven()) this.dAddOffset(1,0);			 while(!this.isProbablePrime(b)) {
				this.dAddOffset(2,0);
				if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
			}
		}
	}
	else {
				var x = new Array(), t = a&7;
		x.length = (a>>3)+1;
		b.nextBytes(x);
		if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
		this.fromString(x,256);
	}
}

function bnToByteArray() {
	var i = this.t, r = new Array();
	r[0] = this.s;
	var p = this.DB-(i*this.DB)%8, d, k = 0;
	if(i-- > 0) {
		if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
			r[k++] = d|(this.s<<(this.DB-p));
		while(i >= 0) {
			if(p < 8) {
				d = (this[i]&((1<<p)-1))<<(8-p);
				d |= this[--i]>>(p+=this.DB-8);
			}
			else {
				d = (this[i]>>(p-=8))&0xff;
				if(p <= 0) { p += this.DB; --i; }
			}
			if((d&0x80) != 0) d |= -256;
			if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
			if(k > 0 || d != this.s) r[k++] = d;
		}
	}
	return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

function bnpBitwiseTo(a,op,r) {
	var i, f, m = Math.min(a.t,this.t);
	for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
	if(a.t < this.t) {
		f = a.s&this.DM;
		for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
		r.t = this.t;
	}
	else {
		f = this.s&this.DM;
		for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
		r.t = a.t;
	}
	r.s = op(this.s,a.s);
	r.clamp();
}

function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

function bnNot() {
	var r = nbi();
	for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
	r.t = this.t;
	r.s = ~this.s;
	return r;
}

function bnShiftLeft(n) {
	var r = nbi();
	if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
	return r;
}

function bnShiftRight(n) {
	var r = nbi();
	if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
	return r;
}

function lbit(x) {
	if(x == 0) return -1;
	var r = 0;
	if((x&0xffff) == 0) { x >>= 16; r += 16; }
	if((x&0xff) == 0) { x >>= 8; r += 8; }
	if((x&0xf) == 0) { x >>= 4; r += 4; }
	if((x&3) == 0) { x >>= 2; r += 2; }
	if((x&1) == 0) ++r;
	return r;
}

function bnGetLowestSetBit() {
	for(var i = 0; i < this.t; ++i)
		if(this[i] != 0) return i*this.DB+lbit(this[i]);
	if(this.s < 0) return this.t*this.DB;
	return -1;
}

function cbit(x) {
	var r = 0;
	while(x != 0) { x &= x-1; ++r; }
	return r;
}

function bnBitCount() {
	var r = 0, x = this.s&this.DM;
	for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
	return r;
}

function bnTestBit(n) {
	var j = Math.floor(n/this.DB);
	if(j >= this.t) return(this.s!=0);
	return((this[j]&(1<<(n%this.DB)))!=0);
}

function bnpChangeBit(n,op) {
	var r = BigInteger.ONE.shiftLeft(n);
	this.bitwiseTo(r,op,r);
	return r;
}

function bnSetBit(n) { return this.changeBit(n,op_or); }

function bnClearBit(n) { return this.changeBit(n,op_andnot); }

function bnFlipBit(n) { return this.changeBit(n,op_xor); }

function bnpAddTo(a,r) {
	var i = 0, c = 0, m = Math.min(a.t,this.t);
	while(i < m) {
		c += this[i]+a[i];
		r[i++] = c&this.DM;
		c >>= this.DB;
	}
	if(a.t < this.t) {
		c += a.s;
		while(i < this.t) {
			c += this[i];
			r[i++] = c&this.DM;
			c >>= this.DB;
		}
		c += this.s;
	}
	else {
		c += this.s;
		while(i < a.t) {
			c += a[i];
			r[i++] = c&this.DM;
			c >>= this.DB;
		}
		c += a.s;
	}
	r.s = (c<0)?-1:0;
	if(c > 0) r[i++] = c;
	else if(c < -1) r[i++] = this.DV+c;
	r.t = i;
	r.clamp();
}

function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

function bnDivideAndRemainder(a) {
	var q = nbi(), r = nbi();
	this.divRemTo(a,q,r);
	return new Array(q,r);
}

function bnpDMultiply(n) {
	this[this.t] = this.am(0,n-1,this,0,0,this.t);
	++this.t;
	this.clamp();
}

function bnpDAddOffset(n,w) {
	if(n == 0) return;
	while(this.t <= w) this[this.t++] = 0;
	this[w] += n;
	while(this[w] >= this.DV) {
		this[w] -= this.DV;
		if(++w >= this.t) this[this.t++] = 0;
		++this[w];
	}
}

function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

function bnPow(e) { return this.exp(e,new NullExp()); }

function bnpMultiplyLowerTo(a,n,r) {
	var i = Math.min(this.t+a.t,n);
	r.s = 0;	 r.t = i;
	while(i > 0) r[--i] = 0;
	var j;
	for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
	for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
	r.clamp();
}

function bnpMultiplyUpperTo(a,n,r) {
	--n;
	var i = r.t = this.t+a.t-n;
	r.s = 0;	 while(--i >= 0) r[i] = 0;
	for(i = Math.max(n-this.t,0); i < a.t; ++i)
		r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
	r.clamp();
	r.drShiftTo(1,r);
}

function Barrett(m) {
		this.r2 = nbi();
	this.q3 = nbi();
	BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
	this.mu = this.r2.divide(m);
	this.m = m;
}

function barrettConvert(x) {
	if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
	else if(x.compareTo(this.m) < 0) return x;
	else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

function barrettReduce(x) {
	x.drShiftTo(this.m.t-1,this.r2);
	if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
	this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
	this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
	while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
	x.subTo(this.r2,x);
	while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

function bnModPow(e,m) {
	var i = e.bitLength(), k, r = nbv(1), z;
	if(i <= 0) return r;
	else if(i < 18) k = 1;
	else if(i < 48) k = 3;
	else if(i < 144) k = 4;
	else if(i < 768) k = 5;
	else k = 6;
	if(i < 8)
		z = new Classic(m);
	else if(m.isEven())
		z = new Barrett(m);
	else {
		z = new Montgomery(m);
	}
	var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
	g[1] = z.convert(this);
	if(k > 1) {
		var g2 = nbi();
		z.sqrTo(g[1],g2);
		while(n <= km) {
			g[n] = nbi();
			z.mulTo(g2,g[n-2],g[n]);
			n += 2;
		}
	}

	var j = e.t-1, w, is1 = true, r2 = nbi(), t;
	i = nbits(e[j])-1;
	while(j >= 0) {
		if(i >= k1) w = (e[j]>>(i-k1))&km;
		else {
			w = (e[j]&((1<<(i+1))-1))<<(k1-i);
			if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
		}

		n = k;
		while((w&1) == 0) { w >>= 1; --n; }
		if((i -= n) < 0) { i += this.DB; --j; }
		if(is1) {				g[w].copyTo(r);
			is1 = false;
		}
		else {
			while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
			if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
			z.mulTo(r2,g[w],r);
		}

		while(j >= 0 && (e[j]&(1<<i)) == 0) {
			z.sqrTo(r,r2); t = r; r = r2; r2 = t;
			if(--i < 0) { i = this.DB-1; --j; }
		}
	}
	return z.revert(r);
}

function bnGCD(a) {
	var x = (this.s<0)?this.negate():this.clone();
	var y = (a.s<0)?a.negate():a.clone();
	if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
	var i = x.getLowestSetBit(), g = y.getLowestSetBit();
	if(g < 0) return x;
	if(i < g) g = i;
	if(g > 0) {
		x.rShiftTo(g,x);
		y.rShiftTo(g,y);
	}
	while(x.signum() > 0) {
		if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
		if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
		if(x.compareTo(y) >= 0) {
			x.subTo(y,x);
			x.rShiftTo(1,x);
		}
		else {
			y.subTo(x,y);
			y.rShiftTo(1,y);
		}
	}
	if(g > 0) y.lShiftTo(g,y);
	return y;
}

function bnpModInt(n) {
	if(n <= 0) return 0;
	var d = this.DV%n, r = (this.s<0)?n-1:0;
	if(this.t > 0)
		if(d == 0) r = this[0]%n;
		else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
	return r;
}

function bnModInverse(m) {
	var ac = m.isEven();
	if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
	var u = m.clone(), v = this.clone();
	var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
	while(u.signum() != 0) {
		while(u.isEven()) {
			u.rShiftTo(1,u);
			if(ac) {
				if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
				a.rShiftTo(1,a);
			}
			else if(!b.isEven()) b.subTo(m,b);
			b.rShiftTo(1,b);
		}
		while(v.isEven()) {
			v.rShiftTo(1,v);
			if(ac) {
				if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
				c.rShiftTo(1,c);
			}
			else if(!d.isEven()) d.subTo(m,d);
			d.rShiftTo(1,d);
		}
		if(u.compareTo(v) >= 0) {
			u.subTo(v,u);
			if(ac) a.subTo(c,a);
			b.subTo(d,b);
		}
		else {
			v.subTo(u,v);
			if(ac) c.subTo(a,c);
			d.subTo(b,d);
		}
	}
	if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
	if(d.compareTo(m) >= 0) return d.subtract(m);
	if(d.signum() < 0) d.addTo(m,d); else return d;
	if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

function bnIsProbablePrime(t) {
	var i, x = this.abs();
	if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
		for(i = 0; i < lowprimes.length; ++i)
			if(x[0] == lowprimes[i]) return true;
		return false;
	}
	if(x.isEven()) return false;
	i = 1;
	while(i < lowprimes.length) {
		var m = lowprimes[i], j = i+1;
		while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
		m = x.modInt(m);
		while(i < j) if(m%lowprimes[i++] == 0) return false;
	}
	return x.millerRabin(t);
}

function bnpMillerRabin(t) {
	var n1 = this.subtract(BigInteger.ONE);
	var k = n1.getLowestSetBit();
	if(k <= 0) return false;
	var r = n1.shiftRight(k);
	t = (t+1)>>1;
	if(t > lowprimes.length) t = lowprimes.length;
	var a = nbi();
	for(var i = 0; i < t; ++i) {
				a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
		var y = a.modPow(r,this);
		if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
			var j = 1;
			while(j++ < k && y.compareTo(n1) != 0) {
				y = y.modPowInt(2,this);
				if(y.compareTo(BigInteger.ONE) == 0) return false;
			}
			if(y.compareTo(n1) != 0) return false;
		}
	}
	return true;
}

BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

BigInteger.prototype.square = bnSquare;



function parseBigInt(str,r) {
	return new BigInteger(str,r);
}

function linebrk(s,n) {
	var ret = "";
	var i = 0;
	while(i + n < s.length) {
		ret += s.substring(i,i+n) + "\n";
		i += n;
	}
	return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
	if(b < 0x10)
		return "0" + b.toString(16);
	else {
		return b.toString(16);
	}
}

function pkcs1pad2(s,n) {
	if(n < s.length + 11) {		 alert("Message too long for RSA");
		return null;
	}
	var ba = new Array();
	var i = s.length - 1;
	while(i >= 0 && n > 0) {
		var c = s.charCodeAt(i--);
		if(c < 128) {			 ba[--n] = c;
		}
		else if((c > 127) && (c < 2048)) {
			ba[--n] = (c & 63) | 128;
			ba[--n] = (c >> 6) | 192;
		}
		else {
			ba[--n] = (c & 63) | 128;
			ba[--n] = ((c >> 6) & 63) | 128;
			ba[--n] = (c >> 12) | 224;
		}
	}
	ba[--n] = 0;
	var rng = new SecureRandom();
	var x = new Array();
	while(n > 2) {		 x[0] = 0;
		while(x[0] == 0) rng.nextBytes(x);
		ba[--n] = x[0];
	}
	ba[--n] = 2;
	ba[--n] = 0;
	return new BigInteger(ba);
}

function simplePad(hash)
{
	var len = (this.n.bitLength() / 4) - 1;
	var out = "";
	while(len > 0) {
		out += hash.substring(0, len > hash.length ? hash.length : len);
		len -= hash.length;
	}
	return new BigInteger(out, 16);
}

function RSAKey() {
	this.n = null;
	this.e = 0;
	this.d = null;
	this.p = null;
	this.q = null;
	this.dmp1 = null;
	this.dmq1 = null;
	this.coeff = null;
}

function RSASetPublic(N,E) {
	if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = parseBigInt(N,16);
		this.e = parseInt(E,16);
	}
	else
		alert("Invalid RSA public key");
}

function RSADoPublic(x) {
	return x.modPowInt(this.e, this.n);
}

function RSAEncrypt(text) {
	var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
	if(m == null) return null;
	var c = this.doPublic(m);
	if(c == null) return null;
	var h = c.toString(16);
	if((h.length & 1) == 0) return h; else return "0" + h;
}


RSAKey.prototype.doPublic = RSADoPublic;

RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;



function pkcs1unpad2(d,n) {
	var b = d.toByteArray();
	var i = 0;
	while(i < b.length && b[i] == 0) ++i;
	if(b.length-i != n-1 || b[i] != 2)
		return null;
	++i;
	while(b[i] != 0)
		if(++i >= b.length) return null;
	var ret = "";
	while(++i < b.length) {
		var c = b[i] & 255;
		if(c < 128) {			 ret += String.fromCharCode(c);
		}
		else if((c > 191) && (c < 224)) {
			ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
			++i;
		}
		else {
			ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
			i += 2;
		}
	}
	return ret;
}

function RSASetPrivate(N,E,D) {
	if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = parseBigInt(N,16);
		this.e = parseInt(E,16);
		this.d = parseBigInt(D,16);
	}
	else
		alert("Invalid RSA private key");
}

function RSASetPrivateEx(N,E,D,P,Q,DP,DQ,C) {
	if(N != null && E != null && N.length > 0 && E.length > 0) {
		this.n = parseBigInt(N,16);
		this.e = parseInt(E,16);
		this.d = parseBigInt(D,16);
		this.p = parseBigInt(P,16);
		this.q = parseBigInt(Q,16);
		this.dmp1 = parseBigInt(DP,16);
		this.dmq1 = parseBigInt(DQ,16);
		this.coeff = parseBigInt(C,16);
	}
	else
		alert("Invalid RSA private key");
}

function RSAGenerate(B,E) {
	var rng = new SecureRandom();
	var qs = B>>1;
	this.e = parseInt(E,16);
	var ee = new BigInteger(E,16);
	for(;;) {
		for(;;) {
			this.p = new BigInteger(B-qs,1,rng);
			if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
		}
		for(;;) {
			this.q = new BigInteger(qs,1,rng);
			if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
		}
		if(this.p.compareTo(this.q) <= 0) {
			var t = this.p;
			this.p = this.q;
			this.q = t;
		}
		var p1 = this.p.subtract(BigInteger.ONE);
		var q1 = this.q.subtract(BigInteger.ONE);
		var phi = p1.multiply(q1);
		if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
			this.n = this.p.multiply(this.q);
			this.d = ee.modInverse(phi);
			this.dmp1 = this.d.mod(p1);
			this.dmq1 = this.d.mod(q1);
			this.coeff = this.q.modInverse(this.p);
			break;
		}
	}
}

function RSADoPrivate(x) {
	if(this.p == null || this.q == null)
		return x.modPow(this.d, this.n);

		var xp = x.mod(this.p).modPow(this.dmp1, this.p);
	var xq = x.mod(this.q).modPow(this.dmq1, this.q);

	while(xp.compareTo(xq) < 0)
		xp = xp.add(this.p);
	return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

function RSASign(x) 
{
	return this.simplePad(x).modPow(this.d, this.n);
}

function RSAVerify(s, m)
{
	m = strip_leading_zeroes(m);
	s = new BigInteger(s, 16);
	s = s.modPowInt(this.e, this.n);
	var str1 = s.toString(16);
	var str2 = m.substring(0, str1.length);
	str1 = str1.substring(0, str2.length);
	return str1 === str2;
}

function strip_leading_zeroes(arg)
{
	var i = 0;
	while(arg.charAt(i) == "0")
		i++;
	return arg.substring(i, arg.length);
}

function RSADecrypt(ctext) {
	var c = parseBigInt(ctext, 16);
	var m = this.doPrivate(c);
	if(m == null) return null;
	return pkcs1unpad2(m, (this.n.bitLength()+7)>>3);
}


function RSAExportPublic()
{
	return hex2b64safe(this.n.toString(16)) + "|" + hex2b64safe(this.e.toString(16));
}

function RSAExportFull()
{
	return hex2b64safe(this.n.toString(16)) + "|" + hex2b64safe(this.e.toString(16)) + "|" + hex2b64safe(this.d.toString(16));
}

RSAKey.prototype.doPrivate = RSADoPrivate;

RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;

RSAKey.prototype.exportPublic = RSAExportPublic;
RSAKey.prototype.exportFull = RSAExportFull;

RSAKey.prototype.sign = RSASign;
RSAKey.prototype.verify = RSAVerify;

RSAKey.prototype.simplePad = simplePad;

function importRSAPublic(str)
{
	var strs = str.split("|");
	if(strs.length != 2)
		return -1;
	if(strs[0].length > 1000 || strs[1].length > 1000)
		return -1;
	strs[0] = b64tohex(strs[0]);
	strs[1] = b64tohex(strs[1]);
	return new RSAKey(new BigInteger(strs[0], 16), new BigInteger(strs[1], 16));
}

function importRSAFull(str)
{
	var strs = str.split("|");
	if(strs.length != 3)
		return -1;
	if((strs[0].length > 1000 || strs[1].length > 1000) || strs[2].length > 1000)
		return -1;
	strs[0] = b64tohex(strs[0]);
	strs[1] = b64tohex(strs[1]);
	strs[2] = b64tohex(strs[2]);
	return new RSAKey(new BigInteger(strs[0], 16), new BigInteger(strs[1], 16), new BigInteger(strs[2], 16));
}

function RSAKey(N, E) {
	this.n = N;
	this.e = E;
	this.d = null;
	this.p = null;
	this.q = null;
	this.dmp1 = null;
	this.dmq1 = null;
	this.coeff = null;
}

function RSAKey(N, E, D) {
	this.n = N;
	this.e = E;
	this.d = D;
	this.p = null;
	this.q = null;
	this.dmp1 = null;
	this.dmq1 = null;
	this.coeff = null;
}



function ECFieldElementFp(q,x) {
		this.x = x;
				this.q = q;
}

function feFpEquals(other) {
		if(other == this) return true;
		return (this.q.equals(other.q) && this.x.equals(other.x));
}

function feFpToBigInteger() {
		return this.x;
}

function feFpNegate() {
		return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}

function feFpAdd(b) {
		return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}

function feFpSubtract(b) {
		return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}

function feFpMultiply(b) {
		return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}

function feFpSquare() {
		return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}

function feFpDivide(b) {
		return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}

ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;


function ECPointFp(curve,x,y,z) {
	this.curve = curve;
	this.x = x;
	this.y = y;
	if(z == null) {
		this.z = BigInteger.ONE;
	}
	else {
		this.z = z;
	}
	this.zinv = null;
}

function pointFpGetX() {
		if(this.zinv == null) {
			this.zinv = this.z.modInverse(this.curve.q);
		}
		var r = this.x.toBigInteger().multiply(this.zinv);
		this.curve.reduce(r);
		return this.curve.fromBigInteger(r);
}

function pointFpGetY() {
		if(this.zinv == null) {
			this.zinv = this.z.modInverse(this.curve.q);
		}
		var r = this.y.toBigInteger().multiply(this.zinv);
		this.curve.reduce(r);
		return this.curve.fromBigInteger(r);
}

function pointFpEquals(other) {
		if(other == this) return true;
		if(this.isInfinity()) return other.isInfinity();
		if(other.isInfinity()) return this.isInfinity();
		var u, v;
				u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
		if(!u.equals(BigInteger.ZERO)) return false;
				v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
		return v.equals(BigInteger.ZERO);
}

function pointFpIsInfinity() {
		if((this.x == null) && (this.y == null)) return true;
		return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}

function pointFpNegate() {
		return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}

function pointFpAdd(b) {
		if(this.isInfinity()) return b;
		if(b.isInfinity()) return this;

				var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
				var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

		if(BigInteger.ZERO.equals(v)) {
				if(BigInteger.ZERO.equals(u)) {
						return this.twice();				 }
	return this.curve.getInfinity();		 }

		var THREE = new BigInteger("3");
		var x1 = this.x.toBigInteger();
		var y1 = this.y.toBigInteger();
		var x2 = b.x.toBigInteger();
		var y2 = b.y.toBigInteger();

		var v2 = v.square();
		var v3 = v2.multiply(v);
		var x1v2 = x1.multiply(v2);
		var zu2 = u.square().multiply(this.z);

				var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
				var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
				var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

		return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpTwice() {
		if(this.isInfinity()) return this;
		if(this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

				var THREE = new BigInteger("3");
		var x1 = this.x.toBigInteger();
		var y1 = this.y.toBigInteger();

		var y1z1 = y1.multiply(this.z);
		var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
		var a = this.curve.a.toBigInteger();

				var w = x1.square().multiply(THREE);
		if(!BigInteger.ZERO.equals(a)) {
			w = w.add(this.z.square().multiply(a));
		}
		w = w.mod(this.curve.q);
						var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
				var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
				var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

		return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}

function pointFpMultiply(k) {
		if(this.isInfinity()) return this;
		if(k.signum() == 0) return this.curve.getInfinity();

		var e = k;
		var h = e.multiply(new BigInteger("3"));

		var neg = this.negate();
		var R = this;

		var i;
		for(i = h.bitLength() - 2; i > 0; --i) {
	R = R.twice();

	var hBit = h.testBit(i);
	var eBit = e.testBit(i);

	if (hBit != eBit) {
			R = R.add(hBit ? this : neg);
	}
		}

		return R;
}

function pointFpMultiplyTwo(j,x,k) {
	var i;
	if(j.bitLength() > k.bitLength())
		i = j.bitLength() - 1;
	else
		i = k.bitLength() - 1;

	var R = this.curve.getInfinity();
	var both = this.add(x);
	while(i >= 0) {
		R = R.twice();
		if(j.testBit(i)) {
			if(k.testBit(i)) {
				R = R.add(both);
			}
			else {
				R = R.add(this);
			}
		}
		else {
			if(k.testBit(i)) {
				R = R.add(x);
			}
		}
		--i;
	}

	return R;
}

ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;


function ECCurveFp(q,a,b) {
		this.q = q;
		this.a = this.fromBigInteger(a);
		this.b = this.fromBigInteger(b);
		this.infinity = new ECPointFp(this, null, null);
		this.reducer = new Barrett(this.q);
}

function curveFpGetQ() {
		return this.q;
}

function curveFpGetA() {
		return this.a;
}

function curveFpGetB() {
		return this.b;
}

function curveFpEquals(other) {
		if(other == this) return true;
		return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
}

function curveFpGetInfinity() {
		return this.infinity;
}

function curveFpFromBigInteger(x) {
		return new ECFieldElementFp(this.q, x);
}

function curveReduce(x) {
		this.reducer.reduce(x);
}

function curveFpDecodePointHex(s) {
		switch(parseInt(s.substr(0,2), 16)) {		 case 0:
	return this.infinity;
		case 2:
		case 3:
		return null;
		case 4:
		case 6:
		case 7:
	var len = (s.length - 2) / 2;
	var xHex = s.substr(2, len);
	var yHex = s.substr(len+2, len);

	return new ECPointFp(this,
					 this.fromBigInteger(new BigInteger(xHex, 16)),
					 this.fromBigInteger(new BigInteger(yHex, 16)));

		default: 	return null;
		}
}

function curveFpEncodePointHex(p) {
	if (p.isInfinity()) return "00";
	var xHex = p.getX().toBigInteger().toString(16);
	var yHex = p.getY().toBigInteger().toString(16);
	var oLen = this.getQ().toString(16).length;
	if ((oLen % 2) != 0) oLen++;
	while (xHex.length < oLen) {
		xHex = "0" + xHex;
	}
	while (yHex.length < oLen) {
		yHex = "0" + yHex;
	}
	return "04" + xHex + yHex;
}

ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.reduce = curveReduce;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
ECCurveFp.prototype.encodePointHex = curveFpEncodePointHex;




function X9ECParameters(curve,g,n,h) {
		this.curve = curve;
		this.g = g;
		this.n = n;
		this.h = h;
}

function x9getCurve() {
		return this.curve;
}

function x9getG() {
		return this.g;
}

function x9getN() {
		return this.n;
}

function x9getH() {
		return this.h;
}

X9ECParameters.prototype.getCurve = x9getCurve;
X9ECParameters.prototype.getG = x9getG;
X9ECParameters.prototype.getN = x9getN;
X9ECParameters.prototype.getH = x9getH;


function fromHex(s) { return new BigInteger(s, 16); }

function secp128r1() {
				var p = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
		var a = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
		var b = fromHex("E87579C11079F43DD824993C2CEE5ED3");
				var n = fromHex("FFFFFFFE0000000075A30D1B9038A115");
		var h = BigInteger.ONE;
		var curve = new ECCurveFp(p, a, b);
		var G = curve.decodePointHex("04"
								+ "161FF7528B899B2D0C28607CA52C5B86"
		+ "CF5AC8395BAFEB13C02DA292DDED7A83");
		return new X9ECParameters(curve, G, n, h);
}

function secp160k1() {
				var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
		var a = BigInteger.ZERO;
		var b = fromHex("7");
				var n = fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");
		var h = BigInteger.ONE;
		var curve = new ECCurveFp(p, a, b);
		var G = curve.decodePointHex("04"
								+ "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB"
								+ "938CF935318FDCED6BC28286531733C3F03C4FEE");
		return new X9ECParameters(curve, G, n, h);
}

function secp160r1() {
				var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
		var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
		var b = fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
				var n = fromHex("0100000000000000000001F4C8F927AED3CA752257");
		var h = BigInteger.ONE;
		var curve = new ECCurveFp(p, a, b);
		var G = curve.decodePointHex("04"
		+ "4A96B5688EF573284664698968C38BB913CBFC82"
		+ "23A628553168947D59DCC912042351377AC5FB32");
		return new X9ECParameters(curve, G, n, h);
}

function secp192k1() {
				var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
		var a = BigInteger.ZERO;
		var b = fromHex("3");
				var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
		var h = BigInteger.ONE;
		var curve = new ECCurveFp(p, a, b);
		var G = curve.decodePointHex("04"
								+ "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
								+ "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");
		return new X9ECParameters(curve, G, n, h);
}

function secp192r1() {
				var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
		var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
		var b = fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1");
				var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
		var h = BigInteger.ONE;
		var curve = new ECCurveFp(p, a, b);
		var G = curve.decodePointHex("04"
								+ "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
								+ "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
		return new X9ECParameters(curve, G, n, h);
}

function secp224r1() {
				var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
		var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
		var b = fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
				var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
		var h = BigInteger.ONE;
		var curve = new ECCurveFp(p, a, b);
		var G = curve.decodePointHex("04"
								+ "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
								+ "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
		return new X9ECParameters(curve, G, n, h);
}

function secp256r1() {
				var p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
		var a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
		var b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
				var n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
		var h = BigInteger.ONE;
		var curve = new ECCurveFp(p, a, b);
		var G = curve.decodePointHex("04"
								+ "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
		+ "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
		return new X9ECParameters(curve, G, n, h);
}

function getSECCurveByName(name) {
		if(name == "secp128r1") return secp128r1();
		if(name == "secp160k1") return secp160k1();
		if(name == "secp160r1") return secp160r1();
		if(name == "secp192k1") return secp192k1();
		if(name == "secp192r1") return secp192r1();
		if(name == "secp224r1") return secp224r1();
		if(name == "secp256r1") return secp256r1();
		return null;
}


var rng_state;
var rng_pool;
var rng_pptr;

function rng_seed_int(x) {
	rng_pool[rng_pptr++] ^= x & 255;
	rng_pool[rng_pptr++] ^= (x >> 8) & 255;
	rng_pool[rng_pptr++] ^= (x >> 16) & 255;
	rng_pool[rng_pptr++] ^= (x >> 24) & 255;
	if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
}

function rng_seed_time() {
	rng_seed_int(new Date().getTime());
}

function hexToDigit(hex) { var code = hex.charCodeAt(); if(code > 57) code -= 7; return code - 48 }
function hexToByte(str, pos) { return hexToDigit(str.charAt(pos)) * 16 + hexToDigit(str.charAt(pos + 1)); }

function rng_seed_hex(hex)
{
	hex.toUpperCase();
	for(var i = 0; i < hex.length; i++) {
		rng_pool[rng_pptr++] ^= hexToByte(hex, i);
		i += 2;
		rng_pptr %= rng_psize;
	}
}

if(rng_pool == null) {
	rng_pool = new Array();
	rng_pptr = 0;
	var t;
	if(window.crypto && window.crypto.getRandomValues) {
				var ua = new Uint8Array(32);
		window.crypto.getRandomValues(ua);
		for(t = 0; t < 32; ++t)
			rng_pool[rng_pptr++] = ua[t];
	}
	if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
				var z = window.crypto.random(32);
		for(t = 0; t < z.length; ++t)
			rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
	}	
	while(rng_pptr < rng_psize) {			t = Math.floor(65536 * Math.random());
		rng_pool[rng_pptr++] = t >>> 8;
		rng_pool[rng_pptr++] = t & 255;
	}
	rng_pptr = 0;
	rng_seed_time();
		}

function rng_get_byte() {
	if(rng_state == null) {
		rng_seed_time();
		rng_state = prng_newstate();
		rng_state.init(rng_pool);
		for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
			rng_pool[rng_pptr] = 0;
		rng_pptr = 0;
			}
		return rng_state.next();
}

function rng_get_bytes(ba) {
	var i;
	for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
}

function SecureRandom() {}

SecureRandom.prototype.nextBytes = rng_get_bytes;

function Arcfour() {
	this.i = 0;
	this.j = 0;
	this.S = new Array();
}

function ARC4init(key) {
	var i, j, t;
	for(i = 0; i < 256; ++i)
		this.S[i] = i;
	j = 0;
	for(i = 0; i < 256; ++i) {
		j = (j + this.S[i] + key[i % key.length]) & 255;
		t = this.S[i];
		this.S[i] = this.S[j];
		this.S[j] = t;
	}
	this.i = 0;
	this.j = 0;
}

function ARC4next() {
	var t;
	this.i = (this.i + 1) & 255;
	this.j = (this.j + this.S[this.i]) & 255;
	t = this.S[this.i];
	this.S[this.i] = this.S[this.j];
	this.S[this.j] = t;
	return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

function prng_newstate() {
	return new Arcfour();
}

var rng_psize = 256;
var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64padchar="=";

function hex2b64safe(orig)
{
	var h = orig;
	while(true) {
		var b64 = hex2b64(h);
		if(strip_leading_zeroes(b64tohex(b64)) == orig)
			return b64;
		h = "0" + h;
	}
}

function hex2b64(h) {
	var i;
	var c;
	var ret = "";
	for(i = 0; i+3 <= h.length; i+=3) {
		c = parseInt(h.substring(i,i+3),16);
		ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
	}
	if(i+1 == h.length) {
		c = parseInt(h.substring(i,i+1),16);
		ret += b64map.charAt(c << 2);
	}
	else if(i+2 == h.length) {
		c = parseInt(h.substring(i,i+2),16);
		ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
	}
	while((ret.length & 3) > 0) ret += b64padchar;
	return ret;
}

function b64tohex(s) {
	var ret = "";
	var i;
	var k = 0;	 var slop;
	for(i = 0; i < s.length; ++i) {
		if(s.charAt(i) == b64padchar) break;
		v = b64map.indexOf(s.charAt(i));
		if(v < 0) continue;
		if(k == 0) {
			ret += int2char(v >> 2);
			slop = v & 3;
			k = 1;
		}
		else if(k == 1) {
			ret += int2char((slop << 2) | (v >> 4));
			slop = v & 0xf;
			k = 2;
		}
		else if(k == 2) {
			ret += int2char(slop);
			ret += int2char(v >> 2);
			slop = v & 3;
			k = 3;
		}
		else {
			ret += int2char((slop << 2) | (v >> 4));
			ret += int2char(v & 0xf);
			k = 0;
		}
	}
	if(k == 1)
		ret += int2char(slop << 2);
	return ret;
}

function b64toBA(s) {
	var h = b64tohex(s);
	var i;
	var a = new Array();
	for(i = 0; 2*i < h.length; ++i) {
		a[i] = parseInt(h.substring(2*i,2*i+2),16);
	}
	return a;
}

function saveKeyDB()
{
	var str = "";
	if(keykeys.length > 0)
		str = exportKeyFull(keykeys[0]);
	for(var i = 1; i < keykeys.length; i++)
		str += "%==%" + exportKeyFull(keykeys[i]);
	localStorage.setItem("keys", str);
}

function loadKeyDB()
{
	var str = localStorage.getItem("keys");
	if(str == null)
		return;
	var str = str.split("%==%");
	for(var i = 0; i < str.length; i++)
		parseKeyFull(str[i], null, false);
}

var out = document.createElement("textarea");
var VERS = 1;

var keytype;
var recommendedent = [32, 64, 96, 128, 192, 256, 384, 512];
var keytypenames = ["RSA-256", "RSA-512", "RSA-768", "RSA-1024", "RSA-1536", "RSA-2048", "RSA-3072", "RSA-4096"];
var keymvers = [1, 1, 1, 1, 1, 1, 1, 1];

function newKey()
{	var user = prompt("Please enter the reddit username to use with the key");
	if(user == null || user == "")
		return;
	var name = prompt("What name would you like for your new key? Keep it short and memorable.");
	if(name == null || name == "")
		return;
	if(getKeyIndex(name) != -1)
		if(confirm("You already have a key under that same name, would you like to replace it?") && confirm("Are you certain? Replaced keys cannot be recovered."))
			removeKey(name);
		else {
			return;
		}
	var type = keytype.value;
	if(bits < 512 && bits < recommendedent[type])
		if(confirm("You lack the recommended entropy for that key type. The recommended entropy is " + recommendedent[type] + " bits and you have an estimated " + bits + " bits. Would you like to add additional entropy?"))
			getEntropy("Enter random text here to increase your entropy pool. Entropy for key mashing is a pessimistic 2 bits per character.");
	rng_seed_hex(hex_sha512(entropy));
	
	var n;
	switch(type)
	{
		case "0":
			n = new RSAKey();
			n.generate("256", "FFFF");
			break;
		case "1":
			n = new RSAKey();
			n.generate("512", "FFFF");
			break;
		case "2":
			n = new RSAKey();
			n.generate("768", "FFFF");
			break;
		case "3":
			n = new RSAKey();
			n.generate("1024", "FFFF");
			break;
		case "4":
			n = new RSAKey();
			n.generate("1536", "FFFF");
			break;
		case "5":
			n = new RSAKey();
			n.generate("2048", "FFFF");
			break;
		case "6":
			n = new RSAKey();
			n.generate("3072", "FFFF");
			break;
		case "7":
			n = new RSAKey();
			n.generate("4096", "FFFF");
			break;
		default:
			return;
	}
	output("Generated new key of type " + keytypenames[type] + " using " + bits + " bits of entropy.\n");
	addKey(name, type, n, true);
	addPKey(user + ":" + name, type, n, true);
	updateKeySelect();
	updatePKeySelect();
	resetEntropy();
}

var keykeys = [];
var keytypes = [];
var keyvalues = [];

function addKey(key, type, value, save)
{
	keykeys.push(key);
	keytypes.push(type);
	keyvalues.push(value);
	if(save)
		saveKeyDB();
}

function getKeyIndex(key)
{
	for(var i = 0; i < keykeys.length; i++)
		if(keykeys[i] == key)
			return i;
	return -1;
}

function getKeyType(index)
{
	return keytypes[index];
}

function getKeyKey(index)
{
	return keyvalues[index];
}

loadKeyDB();

function removeKey(key)
{
	var index = getKeyIndex(key);
	keykeys.splice(index, 1);
	keytypes.splice(index, 1);
	keyvalues.splice(index, 1);
	saveKeyDB();
}

function exportKeyPublic(name)
{
	var index = getKeyIndex(name);
	var type = getKeyType(index);
	var key = getKeyKey(index);
	var kp = "";
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			kp = key.exportPublic();
			break;
		default: 
			return -1;
	}
	if(kp == -1) {
		output("An unknown failure occurred while exporting " + name + ".\n");
		return -1;
	}
	var fin = keymvers[type] + "%%" + type + "%%" + name + "%%" + kp;
	output("Successfully exported public key of type " + keytypenames[type] + ":\n" + fin + "\n");
	return fin;
}

function exportKeyFull(name)
{
	var index = getKeyIndex(name);
	var type = getKeyType(index);
	var key = getKeyKey(index);
	var kp = "";
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			kp = key.exportFull();
			break;
		default: 
			return -1;
	}
	if(kp == -1) {
		output("An unknown failure occurred while exporting " + name + ".\n");
		return -1;
	}
	var fin = keymvers[type] + "%%" + type + "%%" + name + "%%" + kp;
	output("Successfully exported full key of type " + keytypenames[type] + ":\n" + fin + "\n");
	return fin;
}

function ce(a) { return document.createElement(a); }
function gbreak() { var t = document.createElement("span"); t.innerHTML = "&nbsp;&nbsp;"; return t;}
function glbreak() { var t = document.createElement("span"); t.innerHTML = "&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;"; return t;}
function noption(id, name) { var t = document.createElement("option"); t.value = id; t.innerHTML = name; return t; }
function ndoption(name) { var t = document.createElement("option"); t.setAttribute("disabled", ""); t.innerHTML = name; return t; }

var maindiv = ce("div");
maindiv.setAttribute("style", "border-bottom: 3px solid black");
var t = document.getElementsByTagName("body")[0];
t.insertBefore(maindiv, t.childNodes[0]);

t = ce("table");
t.setAttribute("style", "width: 100%");
maindiv.appendChild(t);
var t2 = ce("tr");
t.appendChild(t2);
var topp = ce("td");
t2.appendChild(topp);
t2 = ce("tr");
var middle = ce("td");
t.appendChild(t2);
t2.appendChild(middle);
t2 = ce("tr");
var bottom = ce("td");
t.appendChild(t2);
t2.appendChild(bottom);
t2 = ce("tr");
t.appendChild(t2);
t = ce("td");
t2.appendChild(t);
t.setAttribute("style", "padding: 10px; text-align: center; width: 100%");
t.innerHTML = 'ReddiTrust version Alpha 1.1 - created by <a href="https://www.reddit.com/user/MayaFey_/">/u/MayaFey_</a>';
t = document.createElement("div");
t.setAttribute("style", "box-sizing: border-box; border: 15px solid white; width: 100%");
out.setAttribute("style", "width: 100%; min-height: 8em");

function output(text)
{
	out.innerHTML += text;
}

t.appendChild(out);
bottom.appendChild(t);

var toggleout = document.createElement("button");
toggleout.setAttribute("onClick", "toggleOutput()");
var outhidden = false;

function toggleOutput()
{
	outhidden = !outhidden;
	if(outhidden)
		bottom.setAttribute("style", "display: none");
	else {
		bottom.setAttribute("style", "");
	}
	toggleout.innerHTML = outhidden ? "Show Output" : "Hide Output";
}
toggleOutput();

var entropy = "";
var bits = 0;
var bitcounter = document.createElement("b");

function resetEntropy()
{
	entropy = "You need to stop basing things on your narrow-minded javascript assumptions, Nick";
	bits = 0;
	bitcounter.innerHTML = "Bits: 0";
}

function addEntropy(stuff, approxbits)
{
	entropy += stuff;
	output("Absorbed " + approxbits + " worth of entropy, new internal state: " + hex_sha512(entropy));
	bitcounter.innerHTML = "Bits: " + (bits += approxbits);
}

function getEntropy(text)
{
	var ent = prompt(text);
	if(ent == null)
		return;
	addEntropy(ent, ent.length * 2);
}

resetEntropy();

function parseKeyFull(get, user, update)
{
	var strs = get.split("%%");
	if(strs.length != 4) {
		output("Failed to import key, invalid format\n");
		return;
	}
	if(strs[0] > VERS) {
		output("Failed to import key, key uses a future version of ReddiTrust.\n");
		alert("They key you just tried to import apparently requires a newer version of ReddiTrust.\nIf you have the latest version already, then the key is invalid.");
	}
	var type = strs[1];
	var name = strs[2];
	var key = strs[3];
	if(getKeyIndex(name) != -1) 
		if(confirm("You already have a key of that name, would you like to overwrite?") && confirm("Are you sure!? This action cannot be undone."))
			removeKey(name);
		else {
			return;
		}
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			key = importRSAFull(key);
			break;
		default:
			key = -1;
	}
	if(key == -1) {
		output("An unknown failure occurred importing the key.\n");
		alert("An unexpected failure occurred");
		return;
	}
	output("Successfully imported key of name " + name + "[" + keytypenames[type] + "]\n");
	addKey(name, type, key, update);
	if(update)
		updateKeySelect();
	if(user != null) {
		addPKey(user + ":" + name, type, key, true);
		if(update) 
			updatePKeySelect();
	}	
}

function importKey()
{
	var user = prompt("What username does the key belong to?");
	if(user == null || user == "")
		return;
	var get = prompt("Enter key information here");
	if(get == null || get == "" || get.length > 10000) {
		output("Failed to import key, invalid or null input\n");
		return;
	}
	parseKeyFull(get, user, true);
}

var keyselect = document.createElement("select");
keyselect.appendChild(ndoption("Select a Key"));

function updateKeySelect()
{
	var l = keyselect.childNodes.length;
	while(l-- > 1)
		keyselect.removeChild(keyselect.childNodes[l]);
	for(var i = 0; i < keykeys.length; i++)
		keyselect.appendChild(noption(i, keykeys[i] + " [" + keytypenames[keytypes[i]] + "]"));
}
updateKeySelect();

function removeKeyButton()
{
	removeKey(keykeys[keyselect.value]); /*Unrequired for now, but whatever*/
	updateKeySelect();
}

function exportFullKey()
{
	if(confirm("Are you sure you want to do this?\nExporting your full key includes your secret key, which could be used by others to forge messages that look like they have been sent by you.\nOnly do this for backup or other storage purposes.")) {
		var key = exportKeyFull(keykeys[keyselect.value]);
		if(key != -1)
			alert(key);
	}
}

function exportPublicKey()
{
	var key = exportKeyPublic(keykeys[keyselect.value]);
	if(key != -1)
		alert(key);
}

var pubkeyselect = document.createElement("select");
pubkeyselect.appendChild(ndoption("Select a Key"));

var pkeykeys = [];
var pkeytypes = [];
var pkeyvalues = [];

importPKeyInt("1%%2%%MayaFey_:Main%%pQ38lbA0DXvgrRVG3fgJ1YQTJpHhlZJz05OPL8n7Y+SVA2M6MeSzF6zSHMlDFZhL5iJ3u4Dh6G6mNs2PDEknxSZe5xmrEYiAUL2WnNF+woidkd0KFI3tKFEl7A3bRGDH|//8=");
importPKeyInt("1%%3%%MayaFey_:Backup%%erijCUHL1sW9i6Q0yhgZFVMiy1R0oamJJ1+04/yOB4KExDQbjQ4CFQAJruHrXiXvBBAZFpa067oYu1QvzqOdCS3mvS8GP3JOqXp6t6KijHNOpRxEwnvgQqxJOT7I5nR73Wig34GVvmehKNUkt4tXITRRkh0m72cAfNAvxlImTIs=|//8=");

function addPKey(key, type, value, save)
{
	pkeykeys.push(key);
	pkeytypes.push(type);
	pkeyvalues.push(value);
	if(save)
		savePKeyDB();
}

function getPKeyIndex(key)
{
	for(var i = 0; i < pkeykeys.length; i++)
		if(pkeykeys[i] == key)
			return i;
	return -1;
}

function getPKeyType(index)
{
	return pkeytypes[index];
}

function getPKeyKey(index)
{
	return pkeyvalues[index];
}

function removePKey(key)
{
	var index = getPKeyIndex(key);
	pkeykeys.splice(index, 1);
	pkeytypes.splice(index, 1);
	pkeyvalues.splice(index, 1);
	savePKeyDB();
}

function loadPKeyDB()
{
	var str = localStorage.getItem("pkeys");
	if(str == null)
		return;
	str = str.split("%==%");
	for(var i = 0; i < str.length; i++)
		importPKeyInt(str[i]);
}

function savePKeyDB()
{
	var str = "";
	if(pkeykeys.length > 0)
		str = exportPKeyInt(0);
	for(var i = 1; i < pkeykeys.length; i++) {
		var key = exportPKeyInt(i);
		if(key != -1)
			str += "%==%" + key;
	}
	localStorage.setItem("pkeys", str);
}

loadPKeyDB();

function importManyPub()
{
	str = prompt("Enter key information here:");
	if(str == null)
		return;
	str = str.split("%==%");
	for(var i = 0; i < str.length; i++)
		importPKeyInt(str[i]);
	updatePKeySelect();
}

function exportManyPub()
{
	var str = "";
	if(pkeykeys.length > 0)
		str = exportPKeyInt(0);
	for(var i = 1; i < pkeykeys.length; i++) {
		var key = exportPKeyInt(i);
		if(key != -1)
			str += "%==%" + key;
	}
	output("Exported all possible keys:\n" + str + "\n");
	alert("Full output printed to ReddiTrust console");
}

function exportPKeyInt(index)
{
	var name = pkeykeys[index];
	var key = pkeyvalues[index];
	var type = pkeytypes[index];
	var kp = "";
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			kp = key.exportPublic();
			break;
		default: 
			return -1;
	}
	if(kp == -1) {
		output("An unknown failure occurred while exporting " + name + ".\n");
		return -1;
	}
	var fin = keymvers[type] + "%%" + type + "%%" + name + "%%" + kp;
	output("Successfully exported public key of type " + keytypenames[type] + ":\n" + fin + "\n");
	return fin;
}

function importPKeyInt(str)
{
	if(str.length > 2000)
		return;
	str = str.split("%%");
	if(str.length != 4)
		return;
	if(str[0] > VERS)
		return;
	var type = str[1];
	var name = str[2];
	var key = str[3];
	if(getPKeyIndex(name) != -1) 
		return;
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			key = importRSAPublic(key);
			break;
		default:
			key = -1;
	}
	if(key == -1) {
		output("An unknown failure occurred importing the key.\n");
		alert("An unexpected failure occurred");
		return;
	}
	addPKey(name, type, key, false);
	output("Successfully imported public key of name " + name + "[" + keytypenames[type] + "]\n");
}

function updatePKeySelect()
{
	var l = pubkeyselect.childNodes.length;
	while(l-- > 1)
		pubkeyselect.removeChild(pubkeyselect.childNodes[l]);
	for(var i = 0; i < pkeykeys.length; i++)
		pubkeyselect.appendChild(noption(i, pkeykeys[i] + " [" + keytypenames[pkeytypes[i]] + "]"));
}
updatePKeySelect();

function removePKeyButton()
{
	removePKey(pkeykeys[pubkeyselect.value]); /*Unrequired for now, but whatever*/
	updatePKeySelect();
}

function exportPKeyPublic(name)
{
	var index = getPKeyIndex(name);
	var type = getPKeyType(index);
	var key = getPKeyKey(index);
	var kp = "";
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			kp = key.exportPublic();
			break;
		default: 
			return -1;
	}
	if(kp == -1) {
		output("An unknown failure occurred while exporting " + name + ".\n");
		return -1;
	}
	name = name.split(":")[1];
	var fin = keymvers[type] + "%%" + type + "%%" + name + "%%" + kp;
	output("Successfully exported public key of type " + keytypenames[type] + ":\n" + fin + "\n");
	return fin;
}

function importPKey()
{
	var get = prompt("Enter the username of the key owner here");
	if(get == null || get == "" || get.length > 128) {
		output("Failed to import key, user invalid or null input\n");
		return;
	}
	var user = get;
	get = prompt("Enter key information here");
	if(get == null || get == "" || get.length > 10000) {
		output("Failed to import key, invalid or null input\n");
		return;
	}
	var strs = get.split("%%");
	if(strs.length != 4) {
		output("Failed to import key, invalid format\n");
		return;
	}
	if(strs[0] > VERS) {
		output("Failed to import key, key uses a future version of ReddiTrust.\n");
		alert("They key you just tried to import apparently requires a newer version of ReddiTrust.\nIf you have the latest version already, then the key is invalid.");
		return;
	}
	if(strs[2].length < 1) {
		output("Failed to import key; no name given");
		return;
	}
	var type = strs[1];
	var name = user + ":" + strs[2];
	var key = strs[3];
	if(getPKeyIndex(name) != -1) 
		if(confirm("You already have a key of that name, would you like to overwrite?") && confirm("Are you sure!? This action cannot be undone."))
			removePKey(name);
		else {
			return;
		}
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			key = importRSAPublic(key);
			break;
		default:
			key = -1;
	}
	if(key == -1) {
		output("An unknown failure occurred importing the key.\n");
		alert("An unexpected failure occurred");
		return;
	}
	addPKey(name, type, key, true);
	output("Successfully imported public key of name " + name + "\n");
	updatePKeySelect();
}

function exportTrustPublicKey()
{
	var key = exportPKeyPublic(pkeykeys[pubkeyselect.value]);
	if(key != -1)
		alert(key);
}


var menuselect = document.createElement("select");
menuselect.setAttribute("onChange", "updateMenu()");

var menus = [];

function nMLn(name)
{
	menuselect.appendChild(noption(menus.length, name));
	var t = document.createElement("div");
	t.setAttribute("style", "width: 100%; text-align: center; padding: 5px;");
	menus.push(t);
	return t;
}

function updateMenu()
{
	if(middle.childNodes.length > 0)
		middle.removeChild(middle.childNodes[middle.childNodes.length - 1]);
	middle.appendChild(menus[menuselect.value]);
}

topp.appendChild(gbreak());
topp.appendChild(toggleout);
topp.appendChild(gbreak());
topp.appendChild(menuselect);
topp.appendChild(gbreak());
var t = document.createElement("button");
t.innerHTML = "Update UI";
t.setAttribute("onclick", "updateUIFull();");
topp.appendChild(t);
topp.setAttribute("style", "text-align: center; padding: 5px;");

var cur = nMLn("Generate Keys");

t = document.createElement("b");
t.appendChild(document.createTextNode("Generate Keys:"));
t.setAttribute("style", "text-decoration: underline;");
cur.appendChild(t);
cur.appendChild(gbreak());

t = document.createElement("select");
for(var i = 0; i < keytypenames.length; i++)
	t.appendChild(noption(i, keytypenames[i]));
cur.appendChild(keytype = t);
cur.appendChild(gbreak());

t = document.createElement("button");
t.innerHTML = "Collect Entropy";
t.setAttribute("onclick", "getEntropy('To increase the security of your keys, enter totally random text here. Keyboard mashing, whatever.')");
cur.appendChild(t);
cur.appendChild(gbreak());
cur.appendChild(bitcounter);
cur.appendChild(gbreak());

t = document.createElement("button");
t.innerHTML = "Generate Key";
t.setAttribute("onclick", "newKey()");
cur.appendChild(t);
cur.appendChild(gbreak());

cur = nMLn("Manage Keys");

t = document.createElement("b");
t.appendChild(document.createTextNode("Manage Keys:"));
t.setAttribute("style", "text-decoration: underline;");
cur.appendChild(t);
cur.appendChild(gbreak());
cur.appendChild(keyselect);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Remove";
t.setAttribute("onclick", "removeKeyButton()");
cur.appendChild(t);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Import Key";
t.setAttribute("onclick", "importKey()");
cur.appendChild(t);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Export";
t.setAttribute("onclick", "exportPublicKey()");
cur.appendChild(t);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Export Private";
t.setAttribute("onclick", "exportFullKey()");
cur.appendChild(t);

cur = nMLn("Manage Trust");

t = document.createElement("b");
t.appendChild(document.createTextNode("Manage Trust:"));
t.setAttribute("style", "text-decoration: underline;");
cur.appendChild(t);
cur.appendChild(gbreak());
cur.appendChild(pubkeyselect);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Remove";
t.setAttribute("onclick", "removePKeyButton()");
cur.appendChild(t);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Import";
t.setAttribute("onclick", "importPKey()");
cur.appendChild(t);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Export";
t.setAttribute("onclick", "exportTrustPublicKey()");
cur.appendChild(t);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Import Many";
t.setAttribute("onclick", "importManyPub()");
cur.appendChild(t);
cur.appendChild(gbreak());
t = document.createElement("button");
t.innerHTML = "Export Many";
t.setAttribute("onclick", "exportManyPub()");
cur.appendChild(t);

cur = nMLn("Settings");

function saveMethod()
{
	localStorage.setItem("redditrust_SigMethod", sigmethod.value);
}

var sigmethod = document.createElement("select");
sigmethod.appendChild(noption(0, "Standard"));
sigmethod.appendChild(noption(1, "Superscript (obnoxious, fails on mobile)"));
sigmethod.appendChild(noption(2, "Linked (may be considered spam)"));
sigmethod.appendChild(noption(3, "Invisible (fails on mobile)"));

sigmethod.setAttribute("onChange", "saveMethod()");

sigmethod.value = localStorage.getItem("redditrust_SigMethod");
if(sigmethod.value == undefined || sigmethod.value == "")
	sigmethod.value = "0";

t = document.createElement("b");
t.appendChild(document.createTextNode("Settings:"));
t.setAttribute("style", "text-decoration: underline;");
cur.appendChild(t);
cur.appendChild(glbreak());

t = document.createElement("b");
t.appendChild(document.createTextNode("Signature Method:"));
cur.appendChild(t);
cur.appendChild(gbreak());
cur.appendChild(sigmethod);

updateMenu();

function Signature(username, sig)
{
	this.valid = false;
	var strs = sig.split('%%');
	if(strs.length != 4)
		return;
	if(strs[0] < 1)
		return;
	if(strs[1] < 0)
		return;
	if(strs[2].length == 0 || strs[3].length == 0)
		return;
	this.vers = strs[0];
	this.type = strs[1];
	this.fullname = username + ":" + strs[2];
	this.sig = strs[3];
	this.valid = true;
}

function updateEdits()
{
	var edits = document.getElementsByClassName("edit-usertext");
	for(var i = 0; i < edits.length; i++)
	{
		var edit = edits[i];
		if(edit.getAttribute("__redditrust_processed") == "true")
			continue;
		
		var fid = edit.parentNode.parentNode.parentNode.getElementsByTagName("form")[0].id;
		
		var t = document.createElement("li");
		
		var sign = document.createElement("a");
		sign.innerHTML = "sign";	
		sign.setAttribute("onclick", "sign('" + fid + "')");
		sign.setAttribute("href", "javascript:void(0);");
		t.appendChild(sign);
		
		edit.parentNode.insertAdjacentElement('afterEnd', t);
		
		edit.setAttribute("__redditrust_processed", "true");
	}
}

/* The amount of newlines after comments is inconsistent, strip them off! */
function strip_newlines(text)
{
	var pos = text.length;
	while(text.charAt(--pos) == '\n');
	return text.substring(0, pos + 1);
}

function removeAttributes(thing)
{
	var attributes = [];
	for(var i = 0; i < thing.attributes.length; i++)
		if(thing.attributes[i].name != undefined)
			attributes.push(thing.attributes[i].name.toLowerCase());
	for(var i = 0; i < attributes.length; i++)
		if(attributes[i] != "href")
			thing.removeAttribute(attributes[i]);
	var children = thing.childNodes;
	for(var i = 0; i < children.length; i++)
		if(children[i].nodeType == 1)
			removeAttributes(children[i]);
}

function updateVerify()
{
	var comments = document.getElementsByClassName("usertext-body");
	for(var i = 0; i < comments.length; i++)
	{
		var comment = comments[i];
		if(comment.getAttribute("__redditrust_processed") == "true" || !comment.parentNode.parentNode.classList.contains("entry"))
			continue;
		
		var root = comment.parentNode.parentNode.parentNode;
		var author = root.getAttribute("data-author");
		var md = comment.childNodes[0];
		var sig = getSignature(md, author);
		var tagline = root.getElementsByClassName("entry")[0].childNodes[0];
		var authortag = tagline.getElementsByClassName("author")[0];
		if(authortag == null) {
			comment.setAttribute("__redditrust_processed", "true");
			continue;
		}
		var span = authortag.nextSibling;
		if((span == null || span.nodeType != 1) || span.getAttribute("name") != "__redditrust_verispan") {
			span = document.createElement("span");
			span.setAttribute("name", "__redditrust_verispan");
			authortag.insertAdjacentElement("afterEnd", span);
		}
		if(sig == -1) {
			span.innerHTML = " (Unverified) ";
			span.setAttribute("style", "");
		} else {
			md.setAttribute("__redditrust_has_signature", "true");
			md.removeChild(md.childNodes[md.childNodes.length - 1]);
			md.removeChild(md.childNodes[md.childNodes.length - 1]);
			md.innerHTML = strip_newlines(md.innerHTML);
			for(var j = 0; j < md.childNodes.length; j++)
				if(md.childNodes[j].nodeType == 1)
					removeAttributes(md.childNodes[j]);
			var verify = verify_sig(sig, root.getAttribute("data-fullname") + md.innerHTML);
			md.parentNode.setAttribute("style", "");
			var extra = md.nextSibling;
			if((extra == null || extra.nodeType != 1) || extra.getAttribute("name") != "__redditrust_vericomment") {
				extra = document.createElement("div");
				extra.setAttribute("name", "__redditrust_vericomment");
				md.insertAdjacentElement("afterEnd", extra);
			}
			switch(verify)
			{
				case true:
					span.setAttribute("style", "border: 1px solid white; background-color: green; padding: 2px; color: white;");
					span.setAttribute("title", "Verified using " + keytypenames[sig.type] + ":SHA-512");
					span.innerHTML = "[VERIFIED]";
					extra.innerHTML = "";
					break;
				case false:
					span.setAttribute("style", "border: 1px solid white; background-color: red; padding: 2px; color: white;");
					span.innerHTML = "[FAKE]";
					extra.innerHTML = '<br><br><b style="color: red; text-decoration: underline; font-size: 2em;">This comment is falsified as it contains an invalid signature</b>';
					md.parentNode.setAttribute("style", "background-color: rgba(255, 0, 0, 0.4);");
					break;
				case -1:
					span.setAttribute("style", "border: 1px solid white; background-color: orange; padding: 2px; color: white;");
					span.innerHTML = "[UNVERIFIED]";
					extra.innerHTML = '<br><br><b style="color: orange">This comment cannot be verified as it has a signature claiming to be from a future version of ReddiTrust</b>';
					break;
				case -2:
					span.setAttribute("style", "border: 1px solid white; background-color: orange; padding: 2px; color: white;");
					span.innerHTML = "[UNVERIFIED]";
					extra.innerHTML = '<br><br><b style="color: orange">This comment cannot be verified as you do not have this user\'s public key</b>';
					break;
				case -3:
					span.setAttribute("style", "border: 1px solid white; background-color: orange; padding: 2px; color: white;");
					span.innerHTML = "[UNVERIFIED]";
					extra.innerHTML = '<br><br><b style="color: orange">This comment cannot be verified as signature verification resulted in an unexpected error</b>';
					break;
			}
		}
		if(authortag.innerHTML == "MayaFey_") {
			authortag.setAttribute("style", "color: rgb(158, 98, 183)");
			authortag.innerHTML = "Maya Fey";
		}
		comment.setAttribute("__redditrust_processed", "true")
	}
}

function getSignature(ele, uid)
{
	var last = ele.childNodes[ele.childNodes.length - 2];
	if(last.tagName != "P")
		return -1;
	if(last.childNodes.length == 1 && last.childNodes[0].tagName == "SUP") {
		last = last.childNodes[0];
		if(last.childNodes.length != 1)
			return -1;
		last = last.childNodes[0];
		if(last.tagName != "SUP")
			return -1;
		if(last.childNodes.length != 1)
			return -1;
		last = last.childNodes[0];
		if(last.tagName != "SUP")
			return -1;
		if(last.childNodes.length != 1)
			return -1;
		last = last.childNodes[0];
		if(last.tagName != "SUP")
			return -1;
		if(last.childNodes.length != 1)
			return -1;
		last = last.childNodes[0];
		if(last.tagName != "SUP")
			return -1;
		var sig = last.innerHTML;
		if(sig.length > 2000)
			return -1;
		sig = new Signature(uid, sig);
		if(sig.valid)
			return sig;
		else {
			return -1;
		}
	} else {
		last = last.childNodes[last.childNodes.length - 1];
		if(last.tagName != "A")
			return -1;
		var sig = last.getAttribute("href");
		sig = sig.substr(1, sig.length);
		sig = new Signature(uid, sig);
		if(sig.valid)
			return sig;
		else {
			return -1;
		}
	}
}

function verify_sig(sig, message)
{
	if(sig.vers > VERS)
		return -1;
	var index = getPKeyIndex(sig.fullname);
	if(index == -1)
		return -2;
	var key = getPKeyKey(index);
	var verified = false;
	switch(sig.type)
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			
			verified = key.verify(b64tohex(sig.sig), hex_sha512(message));
			if(verified)
				output("Successfully verified signature of type " + keytypenames[sig.type] + "\n");
			else {
				output("Failed to verify signature of type " + keytypenames[sig.type] + "\nMessage Digest: " + hex_sha512(message) + "\nSignature: " + b64tohex(sig.sig) + "\n");
			}
			break;
		default:
			output("Failed to verify signature of unknown type " + sig.type + "\nMessage Digest: " + hex_sha512(message) + "\nSignature: " + b64tohex(sig.sig) + "\n");
			return -3;
	}
	return verified;
}

function sign_with_key(text, key, name, type)
{
	var sig;
	switch(type) 
	{
		case "0":
		case "1":
		case "2":
		case "3":
		case "4":
		case "5":
		case "6":
		case "7":
			sig = key.sign(text).toString(16);
			output("Successfully created signature of type " + keytypenames[type] + " with key " + key + " for user " + name);
			break;
		default:
			output("An unexpected failure occurred while signing with key of type " + keytypenames[type]);
			return -1;
	}
	sig = hex2b64safe(sig);
	sig = keymvers[type] + "%%" + type + "%%" + name + "%%" + sig;
	switch(sigmethod.value)
	{
		case "0":
			return "\n\nSigned with ReddiTrust Alpha 1.1, using " + keytypenames[type] + "\\SHA-512[.](#" + sig + ")";
		case "1":
			return "\n\n^^^^^" + sig;
		case "2":
			return "\n\nSigned with [ReddiTrust Alpha 1.1](https://github.com/MayaFeyIntensifies/ReddiTrust/releases/tag/vA1.1), using " + keytypenames[type] + "\\SHA-512[.](#" + sig + ")";
		case "3":
			return "\n\n[](#" + sig + ")";
	}
}

function updateMores()
{
	var mores = document.getElementsByClassName("morecomments");
	for(var i = 0; i < mores.length; i++) {
		var more = mores[i];
		if(more.getAttribute("__redditrust_mored") == "true")
			continue;
		
		more.setAttribute("__redditrust_mored", "true");
		more.childNodes[0].setAttribute("onclick", "updateUIFull(); " + more.childNodes[0].getAttribute("onclick"));
	}
}

function updateUIFull()
{
	updateEdits();
	updateVerify();
	updateMores();
	output("Successfully updated UI\n");
}

function sign(fid)
{
	var form = document.getElementById(fid);
	var author = form.parentNode.parentNode.getAttribute("data-author");
	var text = form.getElementsByClassName("usertext-body")[0].childNodes[0];
	var md = form.getElementsByClassName("usertext-edit")[0].getElementsByClassName("md")[0].getElementsByTagName("textarea")[0];
	md.value = strip_newlines(md.value);
	if(text.getAttribute("__redditrust_has_signature") == "true")
		if(!confirm("You already have a signature on that post, do you wish to overwrite?"))
			return;
		else {
			var ht = md.value;
			var start = ht.length;
			var suc = 0;
			while(start-- > 0) {
				if(ht.charAt(start) == '\n')
					suc++;
				else {
					suc = 0;
				}
				if(suc == 2) {
					break;
				}
			}
			md.value = ht.substring(0, start);
		}
	for(var i = 0; i < text.childNodes.length; i++)
		if(text.childNodes[i].nodeType == 1)
			removeAttributes(text.childNodes[i]);
	text = strip_newlines(text.innerHTML);
	var kind = getKeyIndex(keykeys[keyselect.value]);
	if(kind == -1) {
		alert("You have not valid key selected from which to make your signature");
		return;
	}
	var key = getKeyKey(kind);
	var type = getKeyType(kind);
	sig = sign_with_key(hex_sha512(form.parentNode.parentNode.getAttribute("data-fullname") + text), key, keykeys[keyselect.value], type);
	if(sig != -1) {
		md.value += sig;
		form.onsubmit();
		updateUIFull()
	} 
}

updateUIFull();
