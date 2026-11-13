import express from 'express';
import { execFile } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function runPythonBridge(action: string, payload: Record<string, unknown> = {}): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const mainScript = path.join(__dirname, 'main.py');
    const payloadStr = JSON.stringify(payload);
    execFile(
      'python3',
      [mainScript, '--api', action, '--payload', payloadStr],
      { cwd: __dirname, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          try {
            const parsedErr = JSON.parse(stdout.trim());
            reject(new Error(parsedErr.error || stderr || error.message));
          } catch {
            reject(new Error(stderr || error.message));
          }
          return;
        }
        try {
          const result = JSON.parse(stdout.trim());
          resolve(result);
        } catch (parseErr) {
          reject(new Error(`Invalid JSON from Python engine: ${stdout}`));
        }
      }
    );
  });
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '5mb' }));

  // 1. Evaluate SME System Risk & Fetch Database State
  app.get('/api/evaluate', async (req, res) => {
    try {
      const dataSource = (req.query.data_source as string) || 'SIMULATED';
      const daysOffset = parseFloat((req.query.days_offset as string) || '0');
      const result = await runPythonBridge('evaluate', {
        data_source: dataSource,
        days_offset: Number.isNaN(daysOffset) ? 0 : daysOffset,
      });
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Evaluation failed';
      res.status(500).json({ ok: false, error: message });
    }
  });

  // 2. Reset Synthetic SME Dataset
  app.post('/api/reset-simulated', async (_req, res) => {
    try {
      const result = await runPythonBridge('reset_simulated', {});
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Reset failed';
      res.status(500).json({ ok: false, error: message });
    }
  });

  // 3. Clear Real Uploaded Data
  app.post('/api/clear-real', async (_req, res) => {
    try {
      const result = await runPythonBridge('clear_real', {});
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Clear failed';
      res.status(500).json({ ok: false, error: message });
    }
  });

  // 4. Add/Upsert SME Asset
  app.post('/api/assets', async (req, res) => {
    try {
      const result = await runPythonBridge('add_asset', req.body);
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Asset creation failed';
      res.status(400).json({ ok: false, error: message });
    }
  });

  // 5. Add Single Normalised Threat Indicator (SHA-256 Deduplicated)
  app.post('/api/indicators', async (req, res) => {
    try {
      const result = await runPythonBridge('add_indicator', req.body);
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Indicator creation failed';
      res.status(400).json({ ok: false, error: message });
    }
  });

  // 6. Update Indicator Status (OPEN / REMEDIATED)
  app.patch('/api/indicators/:id/status', async (req, res) => {
    try {
      const indicatorId = parseInt(req.params.id, 10);
      const result = await runPythonBridge('update_status', {
        indicator_id: indicatorId,
        status: req.body.status,
        data_source: req.body.data_source || 'SIMULATED',
      });
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Status update failed';
      res.status(400).json({ ok: false, error: message });
    }
  });

  // 7. Batch Import Indicators from CSV via Python `collectors/ingestion_manager.py`
  app.post('/api/import/csv', async (req, res) => {
    try {
      const result = await runPythonBridge('import_csv', req.body);
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'CSV import failed';
      res.status(400).json({ ok: false, error: message });
    }
  });

  // 8. Batch Import Indicators from JSON via Python `collectors/ingestion_manager.py`
  app.post('/api/import/json', async (req, res) => {
    try {
      const result = await runPythonBridge('import_json', req.body);
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'JSON import failed';
      res.status(400).json({ ok: false, error: message });
    }
  });

  // 9. Run 4-Category Synthetic Collectors
  app.post('/api/collect-synthetic', async (_req, res) => {
    try {
      const result = await runPythonBridge('collect_synthetic', {});
      res.json(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Synthetic collection failed';
      res.status(500).json({ ok: false, error: message });
    }
  });

  // 10. Run 150-Asset / 1,000 & 10,000 Indicator Performance Benchmark
  app.post('/api/benchmark', (_req, res) => {
    const benchScript = path.join(__dirname, 'benchmark_performance.py');
    execFile(
      'python3',
      [benchScript, '--json'],
      { cwd: __dirname, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          res.status(500).json({ ok: false, error: stderr || error.message });
          return;
        }
        try {
          res.json(JSON.parse(stdout.trim()));
        } catch {
          res.status(500).json({ ok: false, error: 'Failed to parse benchmark output' });
        }
      }
    );
  });

  // 11. Inspect Raw Python Source Files for University Project Download / Copy
  app.get('/api/python-files', (_req, res) => {
    const filePaths = [
      'main.py',
      'config.py',
      'models.py',
      'database.py',
      'sample_data.py',
      'benchmark_performance.py',
      'requirements.txt',
      'README.md',
      'engine/__init__.py',
      'engine/risk_calculator.py',
      'engine/prioritiser.py',
      'engine/remediation_advisor.py',
      'engine/classifier.py',
      'engine/worked_examples.py',
      'collectors/__init__.py',
      'collectors/base_collector.py',
      'collectors/cti_collector.py',
      'collectors/perimeter_collector.py',
      'collectors/endpoint_collector.py',
      'collectors/identity_collector.py',
      'collectors/ingestion_manager.py',
      'ui/__init__.py',
      'ui/charts.py',
      'ui/pages.py',
      'tests/test_suite_pytest.py',
      'tests/test_math_engine.py',
    ];
    const files = filePaths.map((relPath) => {
      const fullPath = path.join(__dirname, relPath);
      const content = fs.existsSync(fullPath) ? fs.readFileSync(fullPath, 'utf-8') : '';
      return { path: relPath, content };
    });
    res.json({ ok: true, files });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SME Cyber Risk Scorer server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
