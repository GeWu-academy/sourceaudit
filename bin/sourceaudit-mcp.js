#!/usr/bin/env node
'use strict';
require('../lib/mcp').serve().catch(error => {
  console.error(`sourceaudit-mcp: ${error.message}`);
  process.exitCode = 1;
});
