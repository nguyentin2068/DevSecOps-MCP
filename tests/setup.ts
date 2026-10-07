// Keep scanner/server logs out of the test output; tests assert on return values instead.
process.env['LOG_LEVEL'] = process.env['LOG_LEVEL'] ?? 'error';
