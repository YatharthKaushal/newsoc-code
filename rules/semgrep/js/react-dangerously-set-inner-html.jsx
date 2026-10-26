function A({ html }) {
  // ruleid: newsoc.js.react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
function B({ props }) {
  // ruleid: newsoc.js.react-dangerously-set-inner-html
  return <p dangerouslySetInnerHTML={{ __html: props.body }} />;
}
function C({ md }) {
  // ruleid: newsoc.js.react-dangerously-set-inner-html
  return <section dangerouslySetInnerHTML={{ __html: render(md) }} />;
}
function Ok1() {
  // ok: newsoc.js.react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} />;
}
function Ok2({ html }) {
  // ok: newsoc.js.react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
function Ok3({ html }) {
  // ok: newsoc.js.react-dangerously-set-inner-html
  return <div>{html}</div>;
}
