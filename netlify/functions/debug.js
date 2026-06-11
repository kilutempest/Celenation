// Deploy verification marker — if you see this string, deploy v4 is live.
exports.handler = async () => ({
  statusCode: 200,
  headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' },
  body: 'DEPLOY_V4_MARKER_xyz789_no_secrets_here',
});
