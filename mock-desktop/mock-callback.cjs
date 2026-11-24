function validateCallback(pending, payload, recipient, now = Date.now()) {
  if (!pending || payload?.ticket !== pending.ticket || payload?.recipient !== recipient) {
    throw new Error('INVALID_CALLBACK');
  }
  if (now >= pending.expires) throw new Error('EXPIRED_CALLBACK');
}

module.exports = {validateCallback};
