// SYNTHETIC test file. The long lines below were made by a small script to mimic
// the layout of a hidden loader, never its content: the strings are inert words and nothing here
// reaches the network, a process or a file. Semgrep parses this file; nothing runs it.

// identifier chain and eval on one line
// ruleid: newsoc.js.obfuscated-loader
var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};eval(_0x8b9c0d(0));
// identifier chain and new Function
// ruleid: newsoc.js.obfuscated-loader
var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};new Function(_0x8b9c0d(1))();
// identifier chain and a short global.<name> assignment, the layout of a known loader family
// ruleid: newsoc.js.obfuscated-loader
global.i = 'T3-demo';var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};
// the _$_ identifier family with a global['x'] assignment
// ruleid: newsoc.js.obfuscated-loader
global['r']=require;var _$_9f3a=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_$_1c7e,_$_5b2d){var _$_e804=function(_0x5f6a7b){while(--_0x5f6a7b){_$_1c7e['push'](_$_1c7e['shift']());}};_$_e804(++_$_5b2d);}(_$_9f3a,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _$_9f3a[_0x1e2f3a];};
// after real code on the same line
// ruleid: newsoc.js.obfuscated-loader
module.exports = { presets: [] };                                        var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};eval(_0x8b9c0d(0));

// near miss: obfuscated identifiers but no dynamic code on the line (obfuscated-javascript reports this)
// ok: newsoc.js.obfuscated-loader
var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};console.log(_0x8b9c0d(2));
// near miss: Function without new is what stock obfuscator output uses to find the global object
// ok: newsoc.js.obfuscated-loader
var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};Function('return this')();
// near miss: only two identifiers
// ok: newsoc.js.obfuscated-loader
var _0x1a2b3c=1,_0x4d5e6f=2;eval('1+1');
// near miss: one identifier inside a string
// ok: newsoc.js.obfuscated-loader
const label = "_0x1a2b3c"; const other = eval('2+2');
// near miss: hex numbers are not identifiers
// ok: newsoc.js.obfuscated-loader
const wide = 0x1a2b3c + 0x4d5e6f + 0x7a8b9c + 0x2c3d4e; eval('3+3');
// near miss: too short to be generated names
// ok: newsoc.js.obfuscated-loader
const _0x12 = 1, _0x34 = 2, _0x56 = 3, _0x78 = 4; eval('4+4');
// near miss: a long base64 constant
// ok: newsoc.js.obfuscated-loader
const BLOB = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="; eval('5+5');
// near miss: a long global name, no identifiers
// ok: newsoc.js.obfuscated-loader
global.setupDone = true; function isFunction(v){return typeof v === 'function'}
// near miss: a comment
// ok: newsoc.js.obfuscated-loader
// _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) _0x1a2b3c _0x4d5e6f _0x7a8b9c _0x2c3d4e eval(x) 
// near miss: minified-looking UMD code without generated names
// ok: newsoc.js.obfuscated-loader
(function(root,factory){root.demo=factory()}(this,function(){var cache={};return function(n){return cache[n]||(cache[n]=new Function('a','return a+'+n))}}));
// near miss: ordinary code
// ok: newsoc.js.obfuscated-loader
const total = values.map((value) => value * 2).filter(Boolean).reduce((acc, value) => acc + value, 0); eval('6+6');
