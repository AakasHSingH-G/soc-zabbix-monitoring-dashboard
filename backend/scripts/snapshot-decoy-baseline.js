'use strict';

const fs = require('fs');
const path = require('path');
const config = require('../config');

async function makeReadOnly(rootPath) {
  const entries = await fs.promises.readdir(rootPath, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) {
      await makeReadOnly(entryPath);
      await fs.promises.chmod(entryPath, 0o555);
    } else {
      await fs.promises.chmod(entryPath, 0o444);
    }
  }
}

async function makeWritable(rootPath) {
  if (!fs.existsSync(rootPath)) return;
  const entries = await fs.promises.readdir(rootPath, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(rootPath, entry.name);
    if (entry.isDirectory()) await makeWritable(entryPath);
    await fs.promises.chmod(entryPath, entry.isDirectory() ? 0o755 : 0o644);
  }
  await fs.promises.chmod(rootPath, 0o755);
}

async function snapshot() {
  const liveSitePath = path.resolve(config.decoy.liveSitePath);
  const baselinePath = path.resolve(config.decoy.baselinePath);
  if (!fs.existsSync(liveSitePath)) {
    throw new Error(`Decoy site does not exist: ${liveSitePath}`);
  }
  if (liveSitePath === baselinePath) {
    throw new Error('Decoy baseline path must differ from the live site path');
  }

  await makeWritable(baselinePath);
  await fs.promises.rm(baselinePath, { recursive: true, force: true });
  await fs.promises.mkdir(path.dirname(baselinePath), { recursive: true });
  await fs.promises.cp(liveSitePath, baselinePath, {
    recursive: true,
    force: true,
    filter: source => !source.split(path.sep).includes('.git'),
  });
  await makeReadOnly(baselinePath);
  console.log(`Decoy baseline snapshot created: ${baselinePath}`);
}

snapshot().catch(error => {
  console.error(`Decoy baseline snapshot failed: ${error.message}`);
  process.exitCode = 1;
});
