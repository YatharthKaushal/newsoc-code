// SYNTHETIC test file. The long lines below were made by a small script to mimic
// the layout of a hidden loader, never its content: the strings are inert words and nothing here
// reaches the network, a process or a file. Semgrep parses this file; nothing runs it.

module.exports = {
  presets: ['module:demo-preset'],
// code, then hundreds of spaces, then more code on the same line
// ruleid: newsoc.js.hidden-payload-padding
};                                                                                                                                                                                                                                                                                                            global.i = 'T1-demo';var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};

function demo() {
  return 1;
}
// the whole line is padding, then code
// ruleid: newsoc.js.hidden-payload-padding
                                                                                                                                                                                                                                                                                                            global.i = 'T2-demo';var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};
// tabs work as well as spaces
// ruleid: newsoc.js.hidden-payload-padding
demo();																																																																																																																																																						var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};
// no-break spaces are blanks to a JavaScript parser too
// ruleid: newsoc.js.hidden-payload-padding
demo();                                                                                                                                                      var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};
// padding after a block comment
// ruleid: newsoc.js.hidden-payload-padding
/* settings */                                                                                                                        var _0x1a2b3c=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];(function(_0x4d5e6f,_0x7a8b9c){var _0x2c3d4e=function(_0x5f6a7b){while(--_0x5f6a7b){_0x4d5e6f['push'](_0x4d5e6f['shift']());}};_0x2c3d4e(++_0x7a8b9c);}(_0x1a2b3c,0x9));var _0x8b9c0d=function(_0x1e2f3a){return _0x1a2b3c[_0x1e2f3a];};
// exactly 100 spaces after a statement
// ruleid: newsoc.js.hidden-payload-padding
const demo2 = demo();                                                                                                    var _0xaa11bb=["c2FtcGxl","dGVzdA==","ZGVtbw==","cGxhY2Vob2xkZXI=","aW5lcnQ="];console.log(_0xaa11bb.length);

// near miss: a trailing comment is alignment, not a payload
// ok: newsoc.js.hidden-payload-padding
const alignedA = 1;                                                                                                                                                      // a comment pushed to a far column
// ok: newsoc.js.hidden-payload-padding
const alignedB = 2;                                                                                                                        /* a block comment pushed to a far column */
// near miss: only trailing whitespace, nothing after it
// ok: newsoc.js.hidden-payload-padding
const trailing = 3;                                                                                                                                                                                                                                                                                                            
// near miss: the spaces are inside a string literal
// ok: newsoc.js.hidden-payload-padding
const banner = "                                                                                                                                                                                                        centered banner text that is long enough to look like a payload tail";
// near miss: deep indentation (generated code), below the leading-padding limit
// ok: newsoc.js.hidden-payload-padding
                                                                                                                        return computeTheValueOfTheDeeplyNestedGeneratedExpression(argumentNumberOne, argumentNumberTwo, argumentNumberThree);
// near miss: a short run of no-break spaces
// ok: newsoc.js.hidden-payload-padding
const mixed = 7;                                        const alsoMixed = 8; const andOneMore = 9; const andAnother = 10;
// near miss: a gap under 100
// ok: newsoc.js.hidden-payload-padding
const near = 4;                                                            const alsoNear = 5; // a short gap is just alignment
// near miss: leading padding but nothing long after it
// ok: newsoc.js.hidden-payload-padding
                                                                                                                                                                                                                                                                                                            });
// near miss: padding then a lone closing brace
// ok: newsoc.js.hidden-payload-padding
const gap = 6;                                                                                                                                                      }
// near miss: aligned columns inside a template literal
// ok: newsoc.js.hidden-payload-padding
const table = `name                                                                                                                                  value that is aligned in a template literal and runs on for a while longer`;
// near miss: minified-looking code with no padding
// ok: newsoc.js.hidden-payload-padding
!function(e,t){"object"==typeof exports?module.exports=t():e.demo=t()}(this,function(){return{a:1,b:2,c:[1,2,3],d:"some text",e:function(n){return n*2}}});var x=1;
