// WARNING: INTENTIONALLY INSECURE DEMO CODE FOR LOCALAUDIT. DO NOT USE.
export function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function renderBanner(message) {
  document.getElementById("banner").innerHTML = message;
}
