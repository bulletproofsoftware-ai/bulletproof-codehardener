#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { statusCommand } from './commands/status.js';
import { findingsCommand } from './commands/findings.js';
import { scoreCommand } from './commands/score.js';

const program = new Command();

program
  .name('codehardener')
  .description('Code Hardener CLI — security scanning for AI-first developers')
  .version('0.1.0');

program
  .command('scan')
  .description('Run a security scan on the current project')
  .option('-p, --profile <profile>', 'scan profile (quick|standard|comprehensive|auto)', 'auto')
  .option('-s, --scanners <scanners...>', 'specific scanners to run')
  .option('--url <url>', 'Code Hardener API URL', process.env.CODEHARDENER_URL || 'http://localhost:4000')
  .option('--api-key <key>', 'API key', process.env.CODEHARDENER_API_KEY)
  .option('--wait', 'wait for scan to complete', true)
  .option('--no-wait', 'return immediately after queueing scan')
  .option('--json', 'output as JSON')
  .action(scanCommand);

program
  .command('status <scanId>')
  .description('Check the status of a scan')
  .option('--url <url>', 'Code Hardener API URL', process.env.CODEHARDENER_URL || 'http://localhost:4000')
  .option('--api-key <key>', 'API key', process.env.CODEHARDENER_API_KEY)
  .option('--json', 'output as JSON')
  .action(statusCommand);

program
  .command('findings <scanId>')
  .description('Get findings from a completed scan')
  .option('--severity <severity>', 'filter by severity (critical|high|medium|low)')
  .option('--limit <n>', 'max findings to show', '20')
  .option('--url <url>', 'Code Hardener API URL', process.env.CODEHARDENER_URL || 'http://localhost:4000')
  .option('--api-key <key>', 'API key', process.env.CODEHARDENER_API_KEY)
  .option('--json', 'output as JSON')
  .action(findingsCommand);

program
  .command('score [projectId]')
  .description('Get security score for a project')
  .option('--url <url>', 'Code Hardener API URL', process.env.CODEHARDENER_URL || 'http://localhost:4000')
  .option('--api-key <key>', 'API key', process.env.CODEHARDENER_API_KEY)
  .option('--json', 'output as JSON')
  .action(scoreCommand);

program.parse();
