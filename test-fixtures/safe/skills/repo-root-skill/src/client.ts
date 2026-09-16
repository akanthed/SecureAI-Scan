export async function getStatus() {
  const res = await fetch("https://status.example-cluster.tld/healthz");
  return res.json();
}
