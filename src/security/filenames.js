export function safeDownloadName(value = 'document') {
  const cleaned = String(value)
    .replace(/[\r\n\u0000-\u001f\u007f]/g, '')
    .replace(/[\\/"<>:|?*]/g, '_')
    .trim()
    .replace(/^\.+$/, '');
  return (cleaned || 'document').slice(0, 160);
}

export function safeSearchTerm(value = '') {
  return String(value).trim().slice(0, 100).replace(/[%,]/g, ' ');
}
