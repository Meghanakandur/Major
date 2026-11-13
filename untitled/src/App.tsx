import React, { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Copy,
  FileCode2,
  Search,
  Sliders,
  Upload,
} from 'lucide-react';

// ============================================================================
// 1. TYPE DEFINITIONS (Mirroring Python 3.11 dataclasses in `models.py` & `engine/`)
// ============================================================================
type RiskTier = 'Low' | 'Medium' | 'Moderate' | 'High' | 'Critical';
type DataSource = 'SIMULATED' | 'REAL';

interface Asset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  criticality_score: number;
  is_internet_facing: boolean;
  owner_department: string;
  ip_or_hostname: string;
  data_source: DataSource;
  created_at: string;
}

interface EvaluatedIndicatorDetail {
  indicator_id: number;
  sha256_hash: string;
  asset_id: string;
  category: string;
  indicator_type: string;
  identifier_key: string;
  title: string;
  s0: number;
  confidence_c: number;
  decay_lambda: number;
  elapsed_days: number;
  temporal_decay_d: number;
  omega_kev: number;
  psi_exp: number;
  gamma_ctrl: number;
  context_phi: number;
  effective_severity_s: number;
  weighted_impact_cs: number;
  survival_term: number;
  remediation_effort_e: number;
}

interface AssetRiskResult {
  asset: Asset;
  weight_w_i: number;
  criticality_modifier: number;
  open_indicator_count: number;
  survival_product: number;
  combined_threat_prob: number;
  risk_score_r_i: number;
  risk_tier: RiskTier;
  evaluated_indicators: EvaluatedIndicatorDetail[];
}

interface RemediationPriorityItem {
  rank: number;
  indicator_id: number;
  sha256_hash: string;
  asset_id: string;
  asset_name: string;
  category: string;
  identifier_key: string;
  title: string;
  current_asset_risk_r_i: number;
  counterfactual_risk_r_i_minus_k: number;
  risk_reduction_delta: number;
  remediation_effort_e: number;
  omega_kev: number;
  rpi_score: number;
}

interface AutomatedRemediationRecommendation {
  priority_rank: number;
  indicator_id: number;
  sha256_hash: string;
  asset_id: string;
  asset_name: string;
  asset_type: string;
  asset_criticality_a_i: number;
  asset_weight_w_i: number;
  is_internet_facing: boolean;
  exposure_psi: number;
  category: string;
  indicator_type: string;
  identifier_key: string;
  finding_domain_code: string;
  finding_domain_label: string;
  recommendation_headline: string;
  practical_action_steps: string[];
  why_generated_explanation: string;
  urgency_level: RiskTier;
  is_cisa_kev: boolean;
  epss_score: number;
  omega_kev_multiplier: number;
  control_factor_gamma: number;
  effective_severity_s: number;
  estimated_effort_hours_e_k: number;
  current_asset_risk_r_i: number;
  projected_asset_risk_after_fix: number;
  projected_asset_risk_drop_delta: number;
  current_system_risk_r_sys: number;
  projected_system_risk_after_fix: number;
  projected_system_risk_drop_delta: number;
  rpi_score: number;
  verification_status_note: string;
}

interface WorkedExampleResult {
  example_number: number;
  title: string;
  scenario_description: string;
  formulas_tested: string[];
  inputs: Record<string, unknown>;
  step_by_step_derivation: string[];
  expected_outputs: Record<string, number>;
  engine_outputs: Record<string, number>;
  verified_exact_match: boolean;
}

interface SystemRiskSummary {
  evaluated_at: string;
  data_source_filter: DataSource;
  system_risk_r_sys: number;
  system_risk_tier: RiskTier;
  max_asset_risk: number;
  weighted_mean_asset_risk: number;
  total_assets: number;
  total_open_indicators: number;
  asset_results: AssetRiskResult[];
  remediation_plan: RemediationPriorityItem[];
}

interface DeduplicationLog {
  log_id: number;
  sha256_hash: string;
  asset_id: string;
  category: string;
  identifier_key: string;
  title: string;
  data_source: string;
  detected_at: string;
}

interface BatchIngestionReport {
  source_label: string;
  total_processed: number;
  inserted_unique: number;
  duplicates_suppressed: number;
  validation_errors: number;
  error_messages: string[];
  inserted_hashes: string[];
  duplicate_hashes: string[];
}

interface PythonSourceFile {
  path: string;
  content: string;
}

const CATEGORIES = [
  'External Cyber Threat Intelligence',
  'Perimeter and Attack Surface Exposure',
  'Endpoint Configuration and Patch Indicators',
  'Identity and Authentication Hygiene',
] as const;

const SAMPLE_CSV_PAYLOAD = `asset_id,category,indicator_type,identifier_key,title,base_severity_s0,confidence_c,is_cisa_kev,epss_score,control_factor_gamma,remediation_effort_e,observed_at_t0
AST-001,External Cyber Threat Intelligence,CTI_SHODAN_HONEYPOT_MATCH,GREYNOISE-45.155.205.233,Inbound HTTP header exploit reconnaissance from malicious scanner ASN,0.74,0.88,0,0.32,0.75,1.5,2026-11-08T10:00:00Z
AST-002,Perimeter and Attack Surface Exposure,OPEN_SNMP_UDP_161,UDP-161-SNMPV2-PUBLIC,SNMP v2c service with default community string reachable on WAN interface,0.84,0.95,0,0.29,0.95,1.5,2026-11-01T08:30:00Z
AST-003,Endpoint Configuration and Patch Indicators,CVE_VULNERABILITY,CVE-2024-38063,Windows TCP/IP IPv6 Remote Code Execution Vulnerability on Domain Controller,0.98,0.96,1,0.89,0.80,2.5,2026-11-05T12:00:00Z
AST-006,Identity and Authentication Hygiene,MISSING_MFA_PRIVILEGED,MFA-GAP-FINANCE-DIRECTOR,Conditional Access MFA policy bypass detected on Finance Director cloud account,0.92,1.00,0,0.40,1.00,1.0,2026-11-06T09:15:00Z`;

const SAMPLE_JSON_PAYLOAD = JSON.stringify(
  {
    indicators: [
      {
        indicator_id: 'CVE-2024-21762',
        asset_id: 'AST-002',
        category: 'Endpoint Configuration and Patch Indicators',
        indicator_type: 'CVE_VULNERABILITY',
        severity: 0.98,
        confidence: 0.95,
        is_cisa_kev: true,
        epss_score: 0.94,
        control_factor_gamma: 0.85,
        remediation_effort_e: 3.0,
        timestamp: '2026-11-01T00:00:00Z',
        source: 'JSON_SCANNER_IMPORT',
        description:
          'Intentional duplicate CVE-2024-21762 to test SHA-256 deduplication suppression',
      },
      {
        indicator_id: 'TLS-EXPIRED-CERT-PORTAL',
        asset_id: 'AST-001',
        category: 'Perimeter and Attack Surface Exposure',
        indicator_type: 'EXPIRED_TLS_CERTIFICATE',
        severity: 0.64,
        confidence: 1.0,
        is_cisa_kev: false,
        epss_score: 0.11,
        control_factor_gamma: 0.9,
        remediation_effort_e: 1.0,
        timestamp: '2026-11-09T06:00:00Z',
        source: 'PASSIVE_TLS_MONITOR',
        description:
          'Wildcard TLS certificate on secondary checkout subdomain approaching expiration',
      },
    ],
  },
  null,
  2
);

function getTierColor(tier: RiskTier | string): string {
  switch (tier) {
    case 'Low':
      return '#16A34A';
    case 'Medium':
    case 'Moderate':
      return '#D97706';
    case 'High':
      return '#EA580C';
    case 'Critical':
    default:
      return '#DC2626';
  }
}

export default function App() {
  const [activeNav, setActiveNav] = useState<
    'dashboard' | 'collectors' | 'math' | 'remediation' | 'python'
  >('dashboard');

  const [dataSource, setDataSource] = useState<DataSource>('SIMULATED');
  const [daysOffset, setDaysOffset] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [statusBanner, setStatusBanner] = useState<string | null>(null);

  const [summary, setSummary] = useState<SystemRiskSummary | null>(null);
  const [automatedRecs, setAutomatedRecs] = useState<
    AutomatedRemediationRecommendation[]
  >([]);
  const [workedExamples, setWorkedExamples] = useState<WorkedExampleResult[]>(
    []
  );
  const [remediatedList, setRemediatedList] = useState<
    Array<Record<string, unknown>>
  >([]);
  const [dedupLogs, setDedupLogs] = useState<DeduplicationLog[]>([]);
  const [pythonFiles, setPythonFiles] = useState<PythonSourceFile[]>([]);
  const [selectedPyPath, setSelectedPyPath] = useState<string>(
    'engine/remediation_advisor.py'
  );

  // Search & category filter for Indicator Explorer
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedMathAssetId, setSelectedMathAssetId] =
    useState<string>('AST-002');
  const [urgencyFilter, setUrgencyFilter] = useState<string>('ALL');

  // Configurable SME Effort Assumptions (in hours) for live RPI simulation
  const [useCustomEffort, setUseCustomEffort] = useState<boolean>(false);
  const [effortMfaHours, setEffortMfaHours] = useState<number>(1.0);
  const [effortCveHours, setEffortCveHours] = useState<number>(3.0);
  const [effortPerimHours, setEffortPerimHours] = useState<number>(2.0);
  const [effortCtiHours, setEffortCtiHours] = useState<number>(1.5);

  // Collector & Import state
  const [importMode, setImportMode] = useState<
    'csv' | 'json' | 'manual' | 'asset'
  >('csv');
  const [csvText, setCsvText] = useState<string>(SAMPLE_CSV_PAYLOAD);
  const [jsonText, setJsonText] = useState<string>(SAMPLE_JSON_PAYLOAD);
  const [enableExternalApi, setEnableExternalApi] = useState<boolean>(false);
  const [lastBatchReport, setLastBatchReport] =
    useState<BatchIngestionReport | null>(null);

  // Manual indicator form state
  const [manualAssetId, setManualAssetId] = useState<string>('AST-001');
  const [manualCategory, setManualCategory] = useState<string>(CATEGORIES[0]);
  const [manualType, setManualType] = useState<string>('CTI_THREAT_MATCH');
  const [manualKey, setManualKey] = useState<string>('IOC-2026-9901');
  const [manualTitle, setManualTitle] = useState<string>(
    'Suspicious outbound connection to newly registered command-and-control ASN'
  );
  const [manualS0, setManualS0] = useState<number>(0.8);
  const [manualC, setManualC] = useState<number>(0.9);
  const [manualKev, setManualKev] = useState<boolean>(false);
  const [manualEpss, setManualEpss] = useState<number>(0.28);
  const [manualGamma, setManualGamma] = useState<number>(0.8);
  const [manualEffort, setManualEffort] = useState<number>(2.0);

  // Manual asset form state
  const [newAssetId, setNewAssetId] = useState<string>('AST-007');
  const [newAssetName, setNewAssetName] = useState<string>(
    'Internal Backup NAS Storage Server'
  );
  const [newAssetType, setNewAssetType] = useState<string>('Server');
  const [newAssetCrit, setNewAssetCrit] = useState<number>(4);
  const [newAssetInternet, setNewAssetInternet] = useState<boolean>(false);
  const [newAssetDept, setNewAssetDept] = useState<string>('IT Infrastructure');
  const [newAssetIp, setNewAssetIp] = useState<string>('10.10.5.50');

  const fetchEvaluation = async (
    source: DataSource = dataSource,
    offset: number = daysOffset
  ) => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch(
        `/api/evaluate?data_source=${encodeURIComponent(source)}&days_offset=${offset}`
      );
      const data = await res.json();
      if (!data.ok) {
        throw new Error(data.error || 'Failed to evaluate risk');
      }
      setSummary(data.summary);
      setAutomatedRecs(data.automated_recommendations || []);
      setWorkedExamples(data.worked_examples || []);
      setRemediatedList(data.remediated_indicators || []);
      setDedupLogs(data.deduplication_logs || []);
      if (
        data.summary.asset_results?.length > 0 &&
        !data.summary.asset_results.some(
          (r: AssetRiskResult) => r.asset.asset_id === selectedMathAssetId
        )
      ) {
        setSelectedMathAssetId(data.summary.asset_results[0].asset.asset_id);
      }
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'Error communicating with Python engine'
      );
    } finally {
      setLoading(false);
    }
  };

  const fetchPythonSourceFiles = async () => {
    try {
      const res = await fetch('/api/python-files');
      const data = await res.json();
      if (data.ok && Array.isArray(data.files)) {
        setPythonFiles(data.files);
      }
    } catch {
      // Non-fatal
    }
  };

  useEffect(() => {
    fetchEvaluation(dataSource, daysOffset);
  }, [dataSource, daysOffset]);

  useEffect(() => {
    fetchPythonSourceFiles();
  }, []);

  const handleResetDemoData = async () => {
    setLoading(true);
    setStatusBanner(null);
    try {
      const res = await fetch('/api/reset-simulated', { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        setDataSource('SIMULATED');
        setDaysOffset(0);
        setStatusBanner(
          `Reset synthetic SME testbed: ${data.seed_stats.assets_count} assets, ${data.seed_stats.inserted_indicators} unique indicators inserted, ${data.seed_stats.duplicates_suppressed} SHA-256 duplicates suppressed.`
        );
        await fetchEvaluation('SIMULATED', 0);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleRemediateToggle = async (
    indicatorId: number,
    newStatus: 'OPEN' | 'REMEDIATED'
  ) => {
    try {
      const prevSysRisk = summary?.system_risk_r_sys ?? 0;
      const res = await fetch(`/api/indicators/${indicatorId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus, data_source: dataSource }),
      });
      const data = await res.json();
      if (data.ok) {
        await fetchEvaluation(dataSource, daysOffset);
        setStatusBanner(
          newStatus === 'REMEDIATED'
            ? `Recorded remediation for indicator #${indicatorId} in SQLite. Risk scoring engine has recalculated live asset risk R_i(t) and system risk R_sys (previously ${prevSysRisk.toFixed(2)}).`
            : `Re-opened indicator #${indicatorId} in SQLite and recalculated live risk scores.`
        );
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Status update failed');
    }
  };

  const handleImportCsv = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusBanner(null);
    try {
      const res = await fetch('/api/import/csv', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          csv_text: csvText,
          data_source: dataSource,
          enable_external_api: enableExternalApi,
          source_label: 'CSV_BATCH_COLLECTOR',
        }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error);
      setLastBatchReport(data.report);
      setStatusBanner(
        `CSV Collection Complete: ${data.report.inserted_unique} unique indicators stored in SQLite, ${data.report.duplicates_suppressed} SHA-256 duplicates suppressed.`
      );
      await fetchEvaluation(dataSource, daysOffset);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'CSV import failed');
    }
  };

  const handleImportJson = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusBanner(null);
    try {
      const res = await fetch('/api/import/json', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          json_text: jsonText,
          data_source: dataSource,
          enable_external_api: enableExternalApi,
          source_label: 'JSON_BATCH_COLLECTOR',
        }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error);
      setLastBatchReport(data.report);
      setStatusBanner(
        `JSON Collection Complete: ${data.report.inserted_unique} unique indicators stored in SQLite, ${data.report.duplicates_suppressed} SHA-256 duplicates suppressed.`
      );
      await fetchEvaluation(dataSource, daysOffset);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'JSON import failed');
    }
  };

  const handleManualIndicatorSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusBanner(null);
    try {
      const res = await fetch('/api/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          asset_id: manualAssetId,
          category: manualCategory,
          indicator_type: manualType,
          identifier_key: manualKey,
          title: manualTitle,
          base_severity_s0: manualS0,
          confidence_c: manualC,
          is_cisa_kev: manualKev,
          epss_score: manualEpss,
          control_factor_gamma: manualGamma,
          remediation_effort_e: manualEffort,
          data_source: dataSource,
        }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error);
      if (data.was_inserted) {
        setStatusBanner(
          `Inserted new unique indicator '${manualKey}' (SHA-256: ${data.sha256_hash.slice(0, 16)}...).`
        );
      } else {
        setStatusBanner(
          `SHA-256 Deduplication Blocked Duplicate Indicator '${manualKey}' (Collision Hash: ${data.sha256_hash.slice(0, 16)}...).`
        );
      }
      await fetchEvaluation(dataSource, daysOffset);
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Indicator submission failed'
      );
    }
  };

  const handleAddAssetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setStatusBanner(null);
    try {
      const res = await fetch('/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          asset_id: newAssetId,
          asset_name: newAssetName,
          asset_type: newAssetType,
          criticality_score: newAssetCrit,
          is_internet_facing: newAssetInternet,
          owner_department: newAssetDept,
          ip_or_hostname: newAssetIp,
          data_source: dataSource,
        }),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error);
      setStatusBanner(
        `Saved SME Asset ${data.asset.asset_id} (${data.asset.asset_name}) to SQLite.`
      );
      await fetchEvaluation(dataSource, daysOffset);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Asset creation failed');
    }
  };

  const handleFileUpload = (
    e: React.ChangeEvent<HTMLInputElement>,
    targetFormat: 'csv' | 'json'
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = String(event.target?.result || '');
      if (targetFormat === 'csv') {
        setCsvText(content);
      } else {
        setJsonText(content);
      }
    };
    reader.readAsText(file);
  };

  // Dynamically recompute RPI if the user enables custom effort hour assumptions
  const displayedRecommendations = useMemo(() => {
    const list = automatedRecs.map((rec) => {
      if (!useCustomEffort) return rec;
      let customHours = rec.estimated_effort_hours_e_k;
      if (rec.finding_domain_code === 'MISSING_MFA' || rec.finding_domain_code === 'PRIVILEGED_IDENTITY_GAP') {
        customHours = effortMfaHours;
      } else if (
        rec.finding_domain_code === 'OUTDATED_PATCH_VULN_SOFTWARE' ||
        rec.finding_domain_code === 'ENDPOINT_CONFIG_GAP'
      ) {
        customHours = effortCveHours;
      } else if (rec.finding_domain_code === 'EXPOSED_SERVICE_PERIMETER') {
        customHours = effortPerimHours;
      } else {
        customHours = effortCtiHours;
      }
      const safeHours = Math.max(0.25, customHours);
      const recomputedRpi =
        (rec.projected_asset_risk_drop_delta / safeHours) *
        rec.omega_kev_multiplier;
      return {
        ...rec,
        estimated_effort_hours_e_k: safeHours,
        rpi_score: Number(recomputedRpi.toFixed(2)),
      };
    });

    list.sort((a, b) => b.rpi_score - a.rpi_score);
    return list
      .map((item, idx) => ({ ...item, priority_rank: idx + 1 }))
      .filter(
        (item) => urgencyFilter === 'ALL' || item.urgency_level === urgencyFilter
      );
  }, [
    automatedRecs,
    useCustomEffort,
    effortMfaHours,
    effortCveHours,
    effortPerimHours,
    effortCtiHours,
    urgencyFilter,
  ]);

  const allEvaluatedIndicators = useMemo(() => {
    if (!summary) return [];
    const list: EvaluatedIndicatorDetail[] = [];
    for (const r of summary.asset_results) {
      for (const ind of r.evaluated_indicators) {
        list.push(ind);
      }
    }
    return list.filter((item) => {
      const matchesCat =
        categoryFilter === 'ALL' || item.category === categoryFilter;
      const matchesSearch =
        !searchQuery.trim() ||
        item.identifier_key.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.asset_id.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesCat && matchesSearch;
    });
  }, [summary, categoryFilter, searchQuery]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, { count: number; avgS: number }> = {};
    for (const c of CATEGORIES) {
      counts[c] = { count: 0, avgS: 0 };
    }
    if (!summary) return counts;
    for (const r of summary.asset_results) {
      for (const ind of r.evaluated_indicators) {
        if (!counts[ind.category]) {
          counts[ind.category] = { count: 0, avgS: 0 };
        }
        counts[ind.category].count += 1;
        counts[ind.category].avgS += ind.effective_severity_s;
      }
    }
    for (const c of CATEGORIES) {
      if (counts[c].count > 0) {
        counts[c].avgS = counts[c].avgS / counts[c].count;
      }
    }
    return counts;
  }, [summary]);

  const selectedAssetMath = useMemo(() => {
    if (!summary || summary.asset_results.length === 0) return null;
    return (
      summary.asset_results.find(
        (r) => r.asset.asset_id === selectedMathAssetId
      ) || summary.asset_results[0]
    );
  }, [summary, selectedMathAssetId]);

  const activePyFile = useMemo(() => {
    return (
      pythonFiles.find((f) => f.path === selectedPyPath) ||
      pythonFiles[0] || { path: 'main.py', content: '' }
    );
  }, [pythonFiles, selectedPyPath]);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      {/* ====================================================================
          TOP BAR CONTRACT: 3 Zones separated by gap-8
         ==================================================================== */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 bg-white border-b border-slate-200 sticky top-0 z-30">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveNav('dashboard');
          }}
          className="text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
        >
          SME Cyber Risk Scorer
        </a>

        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600">
          <button
            type="button"
            onClick={() => setActiveNav('dashboard')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeNav === 'dashboard'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Dashboard
          </button>
          <button
            type="button"
            onClick={() => setActiveNav('collectors')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeNav === 'collectors'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Indicator Collection
          </button>
          <button
            type="button"
            onClick={() => setActiveNav('math')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeNav === 'math'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Math Engine
          </button>
          <button
            type="button"
            onClick={() => setActiveNav('remediation')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeNav === 'remediation'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Remediation Advisor
          </button>
          <button
            type="button"
            onClick={() => setActiveNav('python')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
              activeNav === 'python'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent hover:text-slate-900'
            }`}
          >
            Python Source
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={handleResetDemoData}
            className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Reset Demo Dataset
          </button>
        </div>
      </header>

      {/* Mobile Navigation Bar */}
      <div className="flex md:hidden items-center gap-2 overflow-x-auto px-4 py-2 bg-white border-b border-slate-200">
        {(
          [
            ['dashboard', 'Dashboard'],
            ['collectors', 'Collectors'],
            ['math', 'Math Engine'],
            ['remediation', 'Remediation Advisor'],
            ['python', 'Python Code'],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setActiveNav(key)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 ${
              activeNav === key
                ? 'bg-slate-900 text-white'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ====================================================================
          WORKSPACE TOOLBAR: Data Mode Switch + Temporal Decay Time Horizon (t)
         ==================================================================== */}
      <div className="bg-white border-b border-slate-200 px-6 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
              <button
                type="button"
                onClick={() => setDataSource('SIMULATED')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  dataSource === 'SIMULATED'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Simulated SME Data
              </button>
              <button
                type="button"
                onClick={() => setDataSource('REAL')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  dataSource === 'REAL'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Real Uploaded Data
              </button>
            </div>

            <div className="text-xs text-slate-500">
              {dataSource === 'SIMULATED' ? (
                <span>
                  Synthetic SME environment active · Clearly separated from real collected data
                </span>
              ) : (
                <span>
                  Real SME data mode active · Showing user-imported CSV/JSON and manual records
                </span>
              )}
            </div>
          </div>

          {/* Temporal Decay Horizon Slider (t - t0) */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs text-slate-700">
              <Sliders className="w-3.5 h-3.5 text-slate-500" />
              <span className="font-medium whitespace-nowrap">
                Evaluation Horizon (t + Δ days):
              </span>
              <span className="font-mono font-semibold text-slate-900 tabular-nums w-14">
                +{daysOffset}d
              </span>
            </div>
            <input
              type="range"
              min={0}
              max={60}
              step={1}
              value={daysOffset}
              onChange={(e) => setDaysOffset(Number(e.target.value))}
              className="w-36 accent-slate-900 cursor-pointer"
              aria-label="Evaluation Time Horizon Offset in Days"
            />
            {daysOffset > 0 && (
              <button
                type="button"
                onClick={() => setDaysOffset(0)}
                className="text-xs text-slate-500 hover:text-slate-900 underline whitespace-nowrap shrink-0 cursor-pointer"
              >
                Reset to t=0
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
        {errorMsg && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-sm text-red-800 flex items-center justify-between">
            <span>{errorMsg}</span>
            <button
              type="button"
              onClick={() => setErrorMsg(null)}
              className="text-xs font-medium underline ml-4 whitespace-nowrap"
            >
              Dismiss
            </button>
          </div>
        )}

        {statusBanner && (
          <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-lg text-sm text-emerald-900 flex items-center justify-between">
            <span>{statusBanner}</span>
            <button
              type="button"
              onClick={() => setStatusBanner(null)}
              className="text-xs font-medium underline ml-4 whitespace-nowrap"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* ====================================================================
            VIEW 1: EXECUTIVE DASHBOARD
           ==================================================================== */}
        {activeNav === 'dashboard' && summary && (
          <div className="space-y-8">
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-200 pb-6">
              <div>
                <p className="text-xs font-medium text-slate-500">
                  University Major Project · Python 3.11 + SQLite Risk Engine
                </p>
                <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-slate-900 mt-1 text-balance">
                  Lightweight Cybersecurity Risk Scoring System for SMEs
                </h1>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                <span>Collection</span>
                <span aria-hidden="true">→</span>
                <span>Normalisation</span>
                <span aria-hidden="true">→</span>
                <span>SHA-256 Deduplication</span>
                <span aria-hidden="true">→</span>
                <span>Dynamic Scoring</span>
                <span aria-hidden="true">→</span>
                <span>RPI Prioritisation</span>
              </div>
            </div>

            {summary.total_assets === 0 ? (
              <div className="bg-white border border-slate-200 rounded-xl p-12 text-center space-y-4">
                <h2 className="text-lg font-semibold text-slate-900">
                  No SME Assets Found in {dataSource} Mode
                </h2>
                <p className="text-sm text-slate-600 max-w-lg mx-auto">
                  Switch to Simulated SME Data to explore the pre-configured 6-asset
                  testbed, or import real assets and threat indicators in the
                  Indicator Collection view.
                </p>
                <div className="flex items-center justify-center gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setDataSource('SIMULATED')}
                    className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
                  >
                    Switch to Simulated SME Data
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveNav('collectors')}
                    className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 cursor-pointer"
                  >
                    Import Real CSV / JSON Data
                  </button>
                </div>
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                  <div className="bg-white border border-slate-200 rounded-xl p-5">
                    <div className="text-xs font-medium text-slate-500">
                      System Risk Score (R_sys)
                    </div>
                    <div className="mt-2 flex items-baseline justify-between">
                      <span
                        className="text-3xl font-bold font-mono tabular-nums"
                        style={{ color: getTierColor(summary.system_risk_tier) }}
                      >
                        {summary.system_risk_r_sys.toFixed(2)}
                      </span>
                      <span
                        className="text-xs font-semibold"
                        style={{ color: getTierColor(summary.system_risk_tier) }}
                      >
                        {summary.system_risk_tier} Risk
                      </span>
                    </div>
                    <div className="mt-2 text-xs text-slate-500 font-mono tabular-nums">
                      α=0.65 · scale 0–100
                    </div>
                  </div>

                  <div className="bg-white border border-slate-200 rounded-xl p-5">
                    <div className="text-xs font-medium text-slate-500">
                      Max Asset Risk max(R_i)
                    </div>
                    <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
                      {summary.max_asset_risk.toFixed(2)}
                    </div>
                    <div className="mt-2 text-xs text-slate-500 font-mono tabular-nums">
                      0.65 × max(R_i) = {(0.65 * summary.max_asset_risk).toFixed(2)}
                    </div>
                  </div>

                  <div className="bg-white border border-slate-200 rounded-xl p-5">
                    <div className="text-xs font-medium text-slate-500">
                      Weighted Mean Σ(w_i · R_i)
                    </div>
                    <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
                      {summary.weighted_mean_asset_risk.toFixed(2)}
                    </div>
                    <div className="mt-2 text-xs text-slate-500 font-mono tabular-nums">
                      0.35 × Σ(w_i·R_i) ={' '}
                      {(0.35 * summary.weighted_mean_asset_risk).toFixed(2)}
                    </div>
                  </div>

                  <div className="bg-white border border-slate-200 rounded-xl p-5">
                    <div className="text-xs font-medium text-slate-500">
                      Active Unique Indicators
                    </div>
                    <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
                      {summary.total_open_indicators}
                    </div>
                    <div className="mt-2 text-xs text-slate-500">
                      Across {summary.total_assets} monitored SME assets
                    </div>
                  </div>

                  <div className="bg-white border border-slate-200 rounded-xl p-5">
                    <div className="text-xs font-medium text-slate-500">
                      SHA-256 Duplicates Blocked
                    </div>
                    <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
                      {dedupLogs.length}
                    </div>
                    <div className="mt-2 text-xs text-slate-500">
                      {remediatedList.length} indicator(s) remediated
                    </div>
                  </div>
                </div>

                {/* Four Indicator Categories Summary Grid */}
                <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="text-base font-semibold text-slate-900">
                      01. Cybersecurity Indicator Categories Breakdown
                    </h2>
                    <span className="text-xs text-slate-500">
                      Category 1 uses temporal decay λ = 0.05/day · Categories 2–4 use persistent λ = 0.0 until remediation
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 pt-1">
                    {CATEGORIES.map((cat, idx) => {
                      const stats = categoryCounts[cat] || { count: 0, avgS: 0 };
                      const isCti = idx === 0;
                      return (
                        <div
                          key={cat}
                          className="border border-slate-200 rounded-lg p-4 flex flex-col justify-between bg-slate-50/50"
                        >
                          <div>
                            <div className="text-xs font-mono text-slate-500">
                              Category 0{idx + 1} · λ = {isCti ? '0.05/day' : '0.00'}
                            </div>
                            <div className="text-sm font-semibold text-slate-900 mt-1">
                              {cat}
                            </div>
                          </div>
                          <div className="mt-4 pt-3 border-t border-slate-200/80 flex items-baseline justify-between text-xs">
                            <span className="text-slate-600">
                              Open Findings:{' '}
                              <strong className="font-mono text-slate-900 tabular-nums">
                                {stats.count}
                              </strong>
                            </span>
                            <span className="text-slate-600">
                              Mean S(I_ik,t):{' '}
                              <strong className="font-mono text-slate-900 tabular-nums">
                                {stats.avgS.toFixed(3)}
                              </strong>
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* SME Asset Risk Leaderboard Table */}
                <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900">
                        02. SME Asset Risk Ranking & Criticality Weights
                      </h2>
                      <p className="text-xs text-slate-500 mt-0.5 font-mono">
                        w_i = A_i / Σ A_j · R_i(t) = 100 × [1 - Π(1 - C_ik · S(I_ik,t))] × (A_i / 5)^0.5
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveNav('math')}
                      className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors cursor-pointer"
                    >
                      Inspect Step-by-Step Asset Math
                    </button>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-sm">
                      <thead>
                        <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500">
                          <th className="py-3 pr-4">Asset ID</th>
                          <th className="py-3 px-4">Asset Name & Host</th>
                          <th className="py-3 px-4">Type</th>
                          <th className="py-3 px-4 text-right">Crit A_i</th>
                          <th className="py-3 px-4 text-right">Weight w_i</th>
                          <th className="py-3 px-4 text-right">Exposure Ψ_exp</th>
                          <th className="py-3 px-4 text-right">(A_i/5)^0.5</th>
                          <th className="py-3 px-4 text-right">Open Inds</th>
                          <th className="py-3 px-4 text-right">Survival Π</th>
                          <th className="py-3 px-4 text-right">Risk R_i(t)</th>
                          <th className="py-3 pl-4">Classification</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 text-xs">
                        {summary.asset_results.map((r) => {
                          const tierColor = getTierColor(r.risk_tier);
                          return (
                            <tr
                              key={r.asset.asset_id}
                              onClick={() => {
                                setSelectedMathAssetId(r.asset.asset_id);
                                setActiveNav('math');
                              }}
                              className="hover:bg-slate-50 transition-colors cursor-pointer"
                            >
                              <td className="py-3 pr-4 font-mono font-semibold text-slate-900 whitespace-nowrap">
                                {r.asset.asset_id}
                              </td>
                              <td className="py-3 px-4">
                                <div className="font-medium text-slate-900">
                                  {r.asset.asset_name}
                                </div>
                                <div className="text-slate-500 font-mono text-[11px]">
                                  {r.asset.ip_or_hostname} · {r.asset.owner_department}
                                </div>
                              </td>
                              <td className="py-3 px-4 text-slate-600 whitespace-nowrap">
                                {r.asset.asset_type}
                              </td>
                              <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-900">
                                {r.asset.criticality_score} / 5
                              </td>
                              <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-700">
                                {r.weight_w_i.toFixed(4)}
                              </td>
                              <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-700">
                                {r.asset.is_internet_facing ? '1.40 (WAN)' : '1.00 (LAN)'}
                              </td>
                              <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-700">
                                {r.criticality_modifier.toFixed(4)}
                              </td>
                              <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-900 font-semibold">
                                {r.open_indicator_count}
                              </td>
                              <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-700">
                                {r.survival_product.toFixed(4)}
                              </td>
                              <td className="py-3 px-4 text-right font-mono tabular-nums font-bold text-slate-900">
                                <div className="flex items-center justify-end gap-2">
                                  <div className="w-16 bg-slate-100 h-2 rounded-xs overflow-hidden hidden sm:block">
                                    <div
                                      className="h-full"
                                      style={{
                                        width: `${Math.min(100, r.risk_score_r_i)}%`,
                                        backgroundColor: tierColor,
                                      }}
                                    />
                                  </div>
                                  <span>{r.risk_score_r_i.toFixed(2)}</span>
                                </div>
                              </td>
                              <td
                                className="py-3 pl-4 font-semibold whitespace-nowrap"
                                style={{ color: tierColor }}
                              >
                                {r.risk_tier}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Top 5 Automated Remediation Recommendations Preview */}
                <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900">
                        03. Top Automated SME Remediation Recommendations (RPI Ranked)
                      </h2>
                      <p className="text-xs text-slate-500 mt-0.5 font-mono">
                        RPI = [(R_i - R_i(-k)) / E_k] × Ω_KEV(k) · Projected counterfactual reductions until remediation is recorded
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveNav('remediation')}
                      className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors cursor-pointer"
                    >
                      Open Full Automated Remediation Advisor
                    </button>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 text-slate-500 font-semibold">
                          <th className="py-2.5 pr-3">Rank</th>
                          <th className="py-2.5 px-3">Urgency</th>
                          <th className="py-2.5 px-3">Asset</th>
                          <th className="py-2.5 px-3">Recommendation & Finding</th>
                          <th className="py-2.5 px-3 text-right">Current R_i</th>
                          <th className="py-2.5 px-3 text-right">Projected R_i(-k)</th>
                          <th className="py-2.5 px-3 text-right">Projected ΔR_i</th>
                          <th className="py-2.5 px-3 text-right">Effort E_k</th>
                          <th className="py-2.5 px-3 text-right">RPI Score</th>
                          <th className="py-2.5 pl-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {displayedRecommendations.slice(0, 5).map((rec) => (
                          <tr key={rec.sha256_hash} className="hover:bg-slate-50">
                            <td className="py-3 pr-3 font-mono font-bold text-slate-900">
                              #{rec.priority_rank}
                            </td>
                            <td
                              className="py-3 px-3 font-semibold whitespace-nowrap"
                              style={{ color: getTierColor(rec.urgency_level) }}
                            >
                              {rec.urgency_level}
                            </td>
                            <td className="py-3 px-3 font-mono text-slate-800 whitespace-nowrap">
                              {rec.asset_id} (A_i={rec.asset_criticality_a_i})
                            </td>
                            <td className="py-3 px-3">
                              <div className="font-semibold text-slate-900">
                                {rec.recommendation_headline}
                              </div>
                              <div className="text-slate-500 font-mono text-[11px]">
                                {rec.finding_domain_label} · {rec.identifier_key}
                              </div>
                            </td>
                            <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-700">
                              {rec.current_asset_risk_r_i.toFixed(2)}
                            </td>
                            <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-700">
                              {rec.projected_asset_risk_after_fix.toFixed(2)}
                            </td>
                            <td className="py-3 px-3 text-right font-mono tabular-nums font-semibold text-emerald-700">
                              -{rec.projected_asset_risk_drop_delta.toFixed(2)}
                            </td>
                            <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-700">
                              {rec.estimated_effort_hours_e_k.toFixed(1)}h
                            </td>
                            <td className="py-3 px-3 text-right font-mono tabular-nums font-bold text-slate-900">
                              {rec.rpi_score.toFixed(2)}
                            </td>
                            <td className="py-3 pl-3 text-right whitespace-nowrap">
                              <button
                                type="button"
                                onClick={() =>
                                  handleRemediateToggle(rec.indicator_id, 'REMEDIATED')
                                }
                                className="px-2.5 py-1 text-xs font-medium text-emerald-800 bg-emerald-50 hover:bg-emerald-100 rounded-md transition-colors cursor-pointer"
                              >
                                Record Fix
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ====================================================================
            VIEW 2: INDICATOR COLLECTION, CSV/JSON IMPORT & SHA-256 DEDUPLICATION
           ==================================================================== */}
        {activeNav === 'collectors' && (
          <div className="space-y-8">
            <div className="border-b border-slate-200 pb-5">
              <p className="text-xs font-medium text-slate-500">
                Python Package: collectors/ · StandardisedIndicatorRecord + SHA-256 Deduplication
              </p>
              <h1 className="text-2xl font-bold text-slate-900 mt-1">
                Cybersecurity Indicator Collection & Normalisation Module
              </h1>
              <p className="text-sm text-slate-600 mt-1 max-w-3xl">
                Collects and normalises indicators across External Cyber Threat
                Intelligence, Perimeter Exposure, Endpoint Configuration & Patching,
                and Identity & Authentication Hygiene. Performs zero unauthorised
                network scanning and falls back gracefully to synthetic or imported
                CSV/JSON data.
              </p>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-1 p-1 bg-slate-200/70 rounded-lg">
                <button
                  type="button"
                  onClick={() => setImportMode('csv')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                    importMode === 'csv'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Import CSV Batch
                </button>
                <button
                  type="button"
                  onClick={() => setImportMode('json')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                    importMode === 'json'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Import JSON Batch
                </button>
                <button
                  type="button"
                  onClick={() => setImportMode('manual')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                    importMode === 'manual'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Single Indicator Entry
                </button>
                <button
                  type="button"
                  onClick={() => setImportMode('asset')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
                    importMode === 'asset'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Add SME Asset
                </button>
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enableExternalApi}
                  onChange={(e) => setEnableExternalApi(e.target.checked)}
                  className="rounded border-slate-300 accent-slate-900"
                />
                <span>
                  Optional Read-Only FIRST.org EPSS Enrichment (Safe fallback when offline)
                </span>
              </label>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-6">
              {importMode === 'csv' && (
                <form onSubmit={handleImportCsv} className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900">
                        Batch CSV Indicator Import (IndicatorIngestionManager.import_from_csv_text)
                      </h2>
                      <p className="text-xs text-slate-500">
                        Upload a CSV file or edit the standardised CSV rows below. Duplicate submissions are automatically suppressed via SHA-256.
                      </p>
                    </div>
                    <label className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer inline-flex items-center gap-1.5">
                      <Upload className="w-3.5 h-3.5" />
                      <span>Load Local .CSV File</span>
                      <input
                        type="file"
                        accept=".csv,text/csv"
                        onChange={(e) => handleFileUpload(e, 'csv')}
                        className="hidden"
                      />
                    </label>
                  </div>

                  <textarea
                    rows={7}
                    value={csvText}
                    onChange={(e) => setCsvText(e.target.value)}
                    className="w-full font-mono text-xs p-3 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-slate-900"
                  />

                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-500">
                      Target Dataset Mode: <strong className="font-mono">{dataSource}</strong>
                    </span>
                    <button
                      type="submit"
                      className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
                    >
                      Normalise & Ingest CSV Batch
                    </button>
                  </div>
                </form>
              )}

              {importMode === 'json' && (
                <form onSubmit={handleImportJson} className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900">
                        Batch JSON Indicator Import (IndicatorIngestionManager.import_from_json_text)
                      </h2>
                      <p className="text-xs text-slate-500">
                        Includes an intentional duplicate CVE-2024-21762 entry to demonstrate live SHA-256 collision detection.
                      </p>
                    </div>
                    <label className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg cursor-pointer inline-flex items-center gap-1.5">
                      <Upload className="w-3.5 h-3.5" />
                      <span>Load Local .JSON File</span>
                      <input
                        type="file"
                        accept=".json,application/json"
                        onChange={(e) => handleFileUpload(e, 'json')}
                        className="hidden"
                      />
                    </label>
                  </div>

                  <textarea
                    rows={10}
                    value={jsonText}
                    onChange={(e) => setJsonText(e.target.value)}
                    className="w-full font-mono text-xs p-3 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:border-slate-900"
                  />

                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-500">
                      Target Dataset Mode: <strong className="font-mono">{dataSource}</strong>
                    </span>
                    <button
                      type="submit"
                      className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
                    >
                      Normalise & Ingest JSON Batch
                    </button>
                  </div>
                </form>
              )}

              {importMode === 'manual' && (
                <form onSubmit={handleManualIndicatorSubmit} className="space-y-4">
                  <h2 className="text-base font-semibold text-slate-900">
                    Submit Single Standardised Threat Indicator
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Target Asset ID
                      </label>
                      <input
                        type="text"
                        value={manualAssetId}
                        onChange={(e) => setManualAssetId(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg font-mono"
                        required
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Indicator Category
                      </label>
                      <select
                        value={manualCategory}
                        onChange={(e) => setManualCategory(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-white"
                      >
                        {CATEGORIES.map((c) => (
                          <option key={c} value={c}>
                            {c}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Indicator Key / CVE ID
                      </label>
                      <input
                        type="text"
                        value={manualKey}
                        onChange={(e) => setManualKey(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg font-mono"
                        required
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Indicator Sub-Type
                      </label>
                      <input
                        type="text"
                        value={manualType}
                        onChange={(e) => setManualType(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg font-mono"
                        required
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="block font-medium text-slate-700 mb-1">
                        Finding Description
                      </label>
                      <input
                        type="text"
                        value={manualTitle}
                        onChange={(e) => setManualTitle(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg"
                        required
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Base Severity S0(k) [0.05 – 1.00]: {manualS0.toFixed(2)}
                      </label>
                      <input
                        type="range"
                        min={0.05}
                        max={1.0}
                        step={0.01}
                        value={manualS0}
                        onChange={(e) => setManualS0(Number(e.target.value))}
                        className="w-full accent-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Confidence C_ik [0.05 – 1.00]: {manualC.toFixed(2)}
                      </label>
                      <input
                        type="range"
                        min={0.05}
                        max={1.0}
                        step={0.01}
                        value={manualC}
                        onChange={(e) => setManualC(Number(e.target.value))}
                        className="w-full accent-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Compensating Control Γ_ctrl [0.30 – 1.00]: {manualGamma.toFixed(2)}
                      </label>
                      <input
                        type="range"
                        min={0.3}
                        max={1.0}
                        step={0.05}
                        value={manualGamma}
                        onChange={(e) => setManualGamma(Number(e.target.value))}
                        className="w-full accent-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        EPSS Probability [0.00 – 1.00]: {manualEpss.toFixed(2)}
                      </label>
                      <input
                        type="range"
                        min={0.0}
                        max={1.0}
                        step={0.01}
                        value={manualEpss}
                        onChange={(e) => setManualEpss(Number(e.target.value))}
                        className="w-full accent-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Remediation Effort E_k (Hours)
                      </label>
                      <input
                        type="number"
                        min={0.5}
                        max={100}
                        step={0.5}
                        value={manualEffort}
                        onChange={(e) => setManualEffort(Number(e.target.value))}
                        className="w-full px-3 py-1.5 border border-slate-200 rounded-lg font-mono"
                      />
                    </div>
                    <div className="flex items-center pt-5">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={manualKev}
                          onChange={(e) => setManualKev(e.target.checked)}
                          className="accent-slate-900"
                        />
                        <span className="font-semibold text-slate-800">
                          Listed in CISA KEV Catalog (Ω_KEV = 1.8)
                        </span>
                      </label>
                    </div>
                  </div>
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
                    >
                      Hash (SHA-256) & Store Indicator
                    </button>
                  </div>
                </form>
              )}

              {importMode === 'asset' && (
                <form onSubmit={handleAddAssetSubmit} className="space-y-4">
                  <h2 className="text-base font-semibold text-slate-900">
                    Register or Update SME IT Asset
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Asset ID
                      </label>
                      <input
                        type="text"
                        value={newAssetId}
                        onChange={(e) => setNewAssetId(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg font-mono"
                        required
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Asset Name
                      </label>
                      <input
                        type="text"
                        value={newAssetName}
                        onChange={(e) => setNewAssetName(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg"
                        required
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Asset Classification
                      </label>
                      <select
                        value={newAssetType}
                        onChange={(e) => setNewAssetType(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg bg-white"
                      >
                        <option value="Server">Server</option>
                        <option value="Workstation">Workstation</option>
                        <option value="Network_Device">Network_Device</option>
                        <option value="Cloud_Identity">Cloud_Identity</option>
                        <option value="Database">Database</option>
                        <option value="Web_Application">Web_Application</option>
                      </select>
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Business Criticality A_i (1 to 5): {newAssetCrit}
                      </label>
                      <input
                        type="range"
                        min={1}
                        max={5}
                        step={1}
                        value={newAssetCrit}
                        onChange={(e) => setNewAssetCrit(Number(e.target.value))}
                        className="w-full accent-slate-900"
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        Owner Department
                      </label>
                      <input
                        type="text"
                        value={newAssetDept}
                        onChange={(e) => setNewAssetDept(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg"
                        required
                      />
                    </div>
                    <div>
                      <label className="block font-medium text-slate-700 mb-1">
                        IP or Hostname
                      </label>
                      <input
                        type="text"
                        value={newAssetIp}
                        onChange={(e) => setNewAssetIp(e.target.value)}
                        className="w-full px-3 py-2 border border-slate-200 rounded-lg font-mono"
                        required
                      />
                    </div>
                  </div>
                  <div className="flex items-center justify-between pt-2">
                    <label className="flex items-center gap-2 text-xs cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newAssetInternet}
                        onChange={(e) => setNewAssetInternet(e.target.checked)}
                        className="accent-slate-900"
                      />
                      <span className="font-semibold text-slate-800">
                        Internet-Facing Asset (Sets Exposure Factor Ψ_exp = 1.4 instead of 1.0)
                      </span>
                    </label>
                    <button
                      type="submit"
                      className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
                    >
                      Save SME Asset
                    </button>
                  </div>
                </form>
              )}
            </div>

            {lastBatchReport && (
              <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-3">
                <h3 className="text-sm font-semibold text-slate-900">
                  Latest Batch Ingestion Report ({lastBatchReport.source_label})
                </h3>
                <div className="flex flex-wrap items-center gap-6 text-xs text-slate-600 font-mono">
                  <span>Total Processed: {lastBatchReport.total_processed}</span>
                  <span>·</span>
                  <span className="text-emerald-700 font-semibold">
                    Unique Inserted: {lastBatchReport.inserted_unique}
                  </span>
                  <span>·</span>
                  <span className="text-amber-700 font-semibold">
                    SHA-256 Duplicates Suppressed: {lastBatchReport.duplicates_suppressed}
                  </span>
                  <span>·</span>
                  <span>Validation Errors: {lastBatchReport.validation_errors}</span>
                </div>
              </div>
            )}

            <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h2 className="text-base font-semibold text-slate-900">
                    Normalised & Deduplicated Indicators in SQLite ({allEvaluatedIndicators.length})
                  </h2>
                  <p className="text-xs text-slate-500">
                    Every record is fingerprinted with SHA-256 over (asset_id | category | indicator_type | identifier_key | status).
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <select
                    value={categoryFilter}
                    onChange={(e) => setCategoryFilter(e.target.value)}
                    className="px-3 py-1.5 text-xs border border-slate-200 rounded-lg bg-white"
                  >
                    <option value="ALL">All 4 Categories</option>
                    {CATEGORIES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
                    <input
                      type="text"
                      placeholder="Filter CVE, key, asset..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-8 pr-3 py-1.5 text-xs border border-slate-200 rounded-lg"
                    />
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-500 font-semibold">
                      <th className="py-2.5 pr-3">Asset</th>
                      <th className="py-2.5 px-3">Category</th>
                      <th className="py-2.5 px-3">Identifier Key</th>
                      <th className="py-2.5 px-3 text-right">S0(k)</th>
                      <th className="py-2.5 px-3 text-right">C_ik</th>
                      <th className="py-2.5 px-3 text-right">λ_k</th>
                      <th className="py-2.5 px-3 text-right">t - t0 (d)</th>
                      <th className="py-2.5 px-3 text-right">D(t,t0)</th>
                      <th className="py-2.5 px-3 text-right">Φ_ik</th>
                      <th className="py-2.5 px-3 text-right">S(I_ik,t)</th>
                      <th className="py-2.5 pl-3">SHA-256 Digest</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {allEvaluatedIndicators.map((ind) => (
                      <tr key={ind.sha256_hash} className="hover:bg-slate-50">
                        <td className="py-2.5 pr-3 font-mono font-semibold text-slate-900">
                          {ind.asset_id}
                        </td>
                        <td className="py-2.5 px-3 text-slate-600">
                          {ind.category}
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="font-mono font-semibold text-slate-900">
                            {ind.identifier_key}
                          </div>
                          <div className="text-slate-500 line-clamp-1">
                            {ind.title}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                          {ind.s0.toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                          {ind.confidence_c.toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                          {ind.decay_lambda.toFixed(2)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                          {ind.elapsed_days.toFixed(1)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                          {ind.temporal_decay_d.toFixed(4)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums">
                          {ind.context_phi.toFixed(3)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-mono tabular-nums font-bold text-slate-900">
                          {ind.effective_severity_s.toFixed(4)}
                        </td>
                        <td
                          className="py-2.5 pl-3 font-mono text-slate-500"
                          title={ind.sha256_hash}
                        >
                          {ind.sha256_hash.slice(0, 14)}…
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-slate-900">
                  SHA-256 Deduplication Collision Log ({dedupLogs.length} Suppressed)
                </h2>
                <p className="text-xs text-slate-500">
                  Audit trail of duplicate threat indicators automatically blocked from SQLite insertion.
                </p>
              </div>
              {dedupLogs.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-500 font-semibold">
                        <th className="py-2 pr-3">Log ID</th>
                        <th className="py-2 px-3">Asset ID</th>
                        <th className="py-2 px-3">Category</th>
                        <th className="py-2 px-3">Duplicate Identifier</th>
                        <th className="py-2 px-3">Colliding SHA-256 Hash</th>
                        <th className="py-2 pl-3">Detected Timestamp (UTC)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 font-mono">
                      {dedupLogs.map((log) => (
                        <tr key={log.log_id} className="hover:bg-slate-50">
                          <td className="py-2.5 pr-3 text-slate-500">#{log.log_id}</td>
                          <td className="py-2.5 px-3 font-semibold text-slate-900">
                            {log.asset_id}
                          </td>
                          <td className="py-2.5 px-3 font-sans text-slate-600">
                            {log.category}
                          </td>
                          <td className="py-2.5 px-3 text-amber-800 font-semibold">
                            {log.identifier_key}
                          </td>
                          <td className="py-2.5 px-3 text-slate-500">
                            {log.sha256_hash.slice(0, 24)}…
                          </td>
                          <td className="py-2.5 pl-3 text-slate-500">
                            {log.detected_at.slice(0, 19)}Z
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ====================================================================
            VIEW 3: STEP-BY-STEP MATHEMATICAL ENGINE & 5 WORKED EXAMPLES
           ==================================================================== */}
        {activeNav === 'math' && summary && (
          <div className="space-y-8">
            <div className="border-b border-slate-200 pb-5 flex flex-wrap items-end justify-between gap-4">
              <div>
                <p className="text-xs font-medium text-slate-500">
                  Python Package: engine/ · Exact Mathematical Specification & Worked Examples
                </p>
                <h1 className="text-2xl font-bold text-slate-900 mt-1">
                  Dynamic Risk Scoring Engine & 5 Worked Numerical Examples
                </h1>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <label className="font-medium text-slate-700">
                  Select Asset to Inspect:
                </label>
                <select
                  value={selectedAssetMath?.asset.asset_id || ''}
                  onChange={(e) => setSelectedMathAssetId(e.target.value)}
                  className="px-3 py-1.5 border border-slate-200 rounded-lg bg-white font-mono font-semibold"
                >
                  {summary.asset_results.map((r) => (
                    <option key={r.asset.asset_id} value={r.asset.asset_id}>
                      {r.asset.asset_id} — {r.asset.asset_name} (R_i ={' '}
                      {r.risk_score_r_i.toFixed(2)})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {selectedAssetMath && (
              <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-6">
                <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
                  <div>
                    <h2 className="text-base font-semibold text-slate-900">
                      Live Numerical Trace for {selectedAssetMath.asset.asset_id}:{' '}
                      {selectedAssetMath.asset.asset_name}
                    </h2>
                    <p className="text-xs text-slate-500 font-mono mt-0.5">
                      A_i = {selectedAssetMath.asset.criticality_score} · w_i ={' '}
                      {selectedAssetMath.weight_w_i.toFixed(4)} · Ψ_exp(i) ={' '}
                      {selectedAssetMath.asset.is_internet_facing ? '1.4' : '1.0'} ·
                      (A_i/5)^0.5 = {selectedAssetMath.criticality_modifier.toFixed(4)}
                    </p>
                  </div>
                  <div className="text-right font-mono">
                    <div className="text-xs text-slate-500">Computed R_i(t)</div>
                    <div
                      className="text-2xl font-bold tabular-nums"
                      style={{ color: getTierColor(selectedAssetMath.risk_tier) }}
                    >
                      {selectedAssetMath.risk_score_r_i.toFixed(2)} / 100 (
                      {selectedAssetMath.risk_tier})
                    </div>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-500 font-sans font-semibold">
                        <th className="py-2 pr-3">Indicator k</th>
                        <th className="py-2 px-3 text-right">S0(k)</th>
                        <th className="py-2 px-3 text-right">λ_k</th>
                        <th className="py-2 px-3 text-right">t - t0</th>
                        <th className="py-2 px-3 text-right">D(t,t0)</th>
                        <th className="py-2 px-3 text-right">Ω_KEV</th>
                        <th className="py-2 px-3 text-right">Ψ_exp</th>
                        <th className="py-2 px-3 text-right">Γ_ctrl</th>
                        <th className="py-2 px-3 text-right">Φ_ik</th>
                        <th className="py-2 px-3 text-right">S(I_ik,t)</th>
                        <th className="py-2 px-3 text-right">C_ik</th>
                        <th className="py-2 pl-3 text-right">
                          Survival (1 - C_ik·S)
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 tabular-nums">
                      {selectedAssetMath.evaluated_indicators.map((d) => (
                        <tr key={d.sha256_hash} className="hover:bg-slate-50">
                          <td className="py-2.5 pr-3 font-semibold text-slate-900">
                            {d.identifier_key}
                          </td>
                          <td className="py-2.5 px-3 text-right">{d.s0.toFixed(3)}</td>
                          <td className="py-2.5 px-3 text-right">
                            {d.decay_lambda.toFixed(2)}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {d.elapsed_days.toFixed(1)}d
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {d.temporal_decay_d.toFixed(4)}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {d.omega_kev.toFixed(1)}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {d.psi_exp.toFixed(1)}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {d.gamma_ctrl.toFixed(2)}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {d.context_phi.toFixed(4)}
                          </td>
                          <td className="py-2.5 px-3 text-right font-bold text-slate-900">
                            {d.effective_severity_s.toFixed(4)}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {d.confidence_c.toFixed(2)}
                          </td>
                          <td className="py-2.5 pl-3 text-right font-semibold text-slate-800">
                            {d.survival_term.toFixed(4)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg font-mono text-xs space-y-1.5 text-slate-800">
                  <div>
                    <strong>Step 1 (Survival Product Π):</strong>{' '}
                    {selectedAssetMath.evaluated_indicators
                      .map((d) => d.survival_term.toFixed(4))
                      .join(' × ') || '1.0000'}{' '}
                    = <strong>{selectedAssetMath.survival_product.toFixed(4)}</strong>
                  </div>
                  <div>
                    <strong>Step 2 (Combined Threat Probability 1 - Π):</strong> 1.0 -{' '}
                    {selectedAssetMath.survival_product.toFixed(4)} ={' '}
                    <strong>{selectedAssetMath.combined_threat_prob.toFixed(4)}</strong>
                  </div>
                  <div>
                    <strong>
                      Step 3 (Final Asset Score R_i(t) with β = 0.5):
                    </strong>{' '}
                    100 × {selectedAssetMath.combined_threat_prob.toFixed(4)} × (
                    {selectedAssetMath.asset.criticality_score}/5)^0.5 ={' '}
                    <strong className="text-slate-900 underline">
                      {selectedAssetMath.risk_score_r_i.toFixed(2)}
                    </strong>
                  </div>
                </div>
              </div>
            )}

            {/* Five Worked Numerical Examples Section */}
            <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
              <div>
                <h2 className="text-base font-semibold text-slate-900">
                  Five Self-Verifying Worked Numerical Examples (engine/worked_examples.py)
                </h2>
                <p className="text-xs text-slate-500">
                  Deterministic verification comparing hand-calculated mathematical values against live Python engine outputs.
                </p>
              </div>
              <div className="space-y-4">
                {workedExamples.map((ex) => (
                  <div
                    key={ex.example_number}
                    className="border border-slate-200 rounded-lg p-4 space-y-3 bg-slate-50/40"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="font-semibold text-sm text-slate-900">
                        Worked Example 0{ex.example_number}: {ex.title}
                      </div>
                      <span className="text-xs font-mono font-semibold text-emerald-700">
                        {ex.verified_exact_match
                          ? 'VERIFIED EXACT MATCH (rel_tol < 1e-9)'
                          : 'MISMATCH'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600">{ex.scenario_description}</p>
                    <div className="bg-white border border-slate-200 rounded-md p-3 font-mono text-xs space-y-1 text-slate-800">
                      {ex.step_by_step_derivation.map((step, i) => (
                        <div key={i}>{step}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ====================================================================
            VIEW 4: AUTOMATED CYBERSECURITY REMEDIATION RECOMMENDATION ENGINE
           ==================================================================== */}
        {activeNav === 'remediation' && summary && (
          <div className="space-y-8">
            <div className="border-b border-slate-200 pb-5">
              <p className="text-xs font-medium text-slate-500">
                Python Module: engine/remediation_advisor.py · Explainable SME Action Planner
              </p>
              <h1 className="text-2xl font-bold text-slate-900 mt-1">
                Automated Cybersecurity Remediation Recommendation Engine
              </h1>
              <p className="text-xs text-slate-600 mt-1">
                Analyses highest-risk SME assets, criticality A_i, CISA KEV status, EPSS probability, missing MFA, outdated patches, and exposed services. Projected risk reductions are counterfactual estimates — actual risk is only reduced when a remediation is recorded in SQLite and recalculated.
              </p>
            </div>

            {/* Configurable SME Remediation Effort Assumptions */}
            <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h2 className="text-sm font-semibold text-slate-900">
                    Configurable SME Remediation Effort Assumptions (Hours E_k)
                  </h2>
                  <p className="text-xs text-slate-500">
                    Adjust estimated engineering hours per finding class to see how E_k dynamically shifts RPI = [(R_i - R_i(-k)) / E_k] × Ω_KEV(k).
                  </p>
                </div>
                <label className="flex items-center gap-2 text-xs font-medium text-slate-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useCustomEffort}
                    onChange={(e) => setUseCustomEffort(e.target.checked)}
                    className="accent-slate-900"
                  />
                  <span>Apply Custom Effort Assumptions</span>
                </label>
              </div>

              {useCustomEffort && (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-2 text-xs">
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">
                      Missing MFA / Identity Fix (Hours): {effortMfaHours}h
                    </label>
                    <input
                      type="range"
                      min={0.5}
                      max={10}
                      step={0.5}
                      value={effortMfaHours}
                      onChange={(e) => setEffortMfaHours(Number(e.target.value))}
                      className="w-full accent-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">
                      Outdated Patch / CVE Fix (Hours): {effortCveHours}h
                    </label>
                    <input
                      type="range"
                      min={0.5}
                      max={16}
                      step={0.5}
                      value={effortCveHours}
                      onChange={(e) => setEffortCveHours(Number(e.target.value))}
                      className="w-full accent-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">
                      Exposed Service / Firewall Fix (Hours): {effortPerimHours}h
                    </label>
                    <input
                      type="range"
                      min={0.5}
                      max={12}
                      step={0.5}
                      value={effortPerimHours}
                      onChange={(e) => setEffortPerimHours(Number(e.target.value))}
                      className="w-full accent-slate-900"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-slate-700 mb-1">
                      External CTI Blocklist / Rule (Hours): {effortCtiHours}h
                    </label>
                    <input
                      type="range"
                      min={0.5}
                      max={10}
                      step={0.5}
                      value={effortCtiHours}
                      onChange={(e) => setEffortCtiHours(Number(e.target.value))}
                      className="w-full accent-slate-900"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Filter by Urgency & Detailed Explainable Cards */}
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <h2 className="text-base font-semibold text-slate-900">
                  Prioritised SME Remediation Recommendations ({displayedRecommendations.length})
                </h2>
                <div className="flex items-center gap-1 p-1 bg-slate-200/70 rounded-lg text-xs">
                  {(['ALL', 'Critical', 'High', 'Medium', 'Low'] as const).map(
                    (urg) => (
                      <button
                        key={urg}
                        type="button"
                        onClick={() => setUrgencyFilter(urg)}
                        className={`px-3 py-1 font-medium rounded-md transition-colors cursor-pointer ${
                          urgencyFilter === urg
                            ? 'bg-white text-slate-900 shadow-xs'
                            : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {urg === 'ALL' ? 'All Urgencies' : `${urg} Urgency`}
                      </button>
                    )
                  )}
                </div>
              </div>

              {displayedRecommendations.map((rec) => (
                <div
                  key={rec.sha256_hash}
                  className="bg-white border border-slate-200 rounded-xl p-6 space-y-4"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 pb-4">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 font-mono">
                        <span className="font-bold text-slate-900">
                          Priority Rank #{rec.priority_rank}
                        </span>
                        <span>·</span>
                        <span
                          className="font-semibold"
                          style={{ color: getTierColor(rec.urgency_level) }}
                        >
                          {rec.urgency_level} Urgency
                        </span>
                        <span>·</span>
                        <span>{rec.finding_domain_label}</span>
                        <span>·</span>
                        <span>
                          {rec.asset_id} ({rec.asset_name}, A_i={rec.asset_criticality_a_i}/5)
                        </span>
                      </div>
                      <h3 className="text-base font-bold text-slate-900">
                        {rec.recommendation_headline}
                      </h3>
                    </div>

                    <div className="flex items-center gap-4">
                      <div className="text-right font-mono">
                        <div className="text-[11px] text-slate-500">
                          RPI Score (Effort: {rec.estimated_effort_hours_e_k.toFixed(1)}h)
                        </div>
                        <div className="text-xl font-bold text-slate-900 tabular-nums">
                          {rec.rpi_score.toFixed(2)}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          handleRemediateToggle(rec.indicator_id, 'REMEDIATED')
                        }
                        className="px-3.5 py-2 text-xs font-semibold text-white bg-slate-900 hover:bg-slate-800 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Record Remediation & Recalculate
                      </button>
                    </div>
                  </div>

                  {/* Why Generated Explanation */}
                  <div className="text-xs text-slate-700 leading-relaxed bg-slate-50 p-3.5 rounded-lg border border-slate-200/80">
                    <strong className="text-slate-900">
                      Why This Recommendation Was Generated:{' '}
                    </strong>
                    {rec.why_generated_explanation}
                  </div>

                  {/* Practical Action Steps & Counterfactual Metrics */}
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 text-xs">
                    <div className="lg:col-span-2 space-y-2">
                      <div className="font-semibold text-slate-900">
                        Recommended Practical SME Remediation Steps:
                      </div>
                      <ol className="list-decimal list-inside space-y-1 text-slate-700">
                        {rec.practical_action_steps.map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ol>
                    </div>

                    <div className="border border-slate-200 rounded-lg p-3.5 font-mono space-y-1.5 bg-slate-50/40">
                      <div className="font-sans font-semibold text-slate-700 pb-1 border-b border-slate-200">
                        Counterfactual Projection (Pre-Fix)
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Current Asset R_i:</span>
                        <span className="font-semibold text-slate-900 tabular-nums">
                          {rec.current_asset_risk_r_i.toFixed(2)}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Projected R_i(-k):</span>
                        <span className="font-semibold text-slate-900 tabular-nums">
                          {rec.projected_asset_risk_after_fix.toFixed(2)}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Projected Asset ΔR_i:</span>
                        <span className="font-bold text-emerald-700 tabular-nums">
                          -{rec.projected_asset_risk_drop_delta.toFixed(2)} pts
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500">Projected System R_sys:</span>
                        <span className="font-semibold text-slate-900 tabular-nums">
                          {rec.current_system_risk_r_sys.toFixed(2)} →{' '}
                          {rec.projected_system_risk_after_fix.toFixed(2)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Verified Completed Remediations History */}
            {remediatedList.length > 0 && (
              <div className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
                <h2 className="text-base font-semibold text-slate-900">
                  Verified Completed Remediations ({remediatedList.length})
                </h2>
                <p className="text-xs text-emerald-800">
                  These remediations have been recorded in SQLite and are reflected in the current recalculated System Risk R_sys = {summary.system_risk_r_sys.toFixed(2)}.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-500 font-semibold">
                        <th className="py-2 pr-3">Asset ID</th>
                        <th className="py-2 px-3">Category</th>
                        <th className="py-2 px-3">Identifier Key</th>
                        <th className="py-2 px-3">Description</th>
                        <th className="py-2 pl-3 text-right">Restore</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      {remediatedList.map((ind) => (
                        <tr key={String(ind.indicator_id)} className="hover:bg-slate-50">
                          <td className="py-2.5 pr-3 font-mono font-semibold">
                            {String(ind.asset_id)}
                          </td>
                          <td className="py-2.5 px-3 text-slate-600">
                            {String(ind.category)}
                          </td>
                          <td className="py-2.5 px-3 font-mono">
                            {String(ind.identifier_key)}
                          </td>
                          <td className="py-2.5 px-3 text-slate-500">
                            {String(ind.title)}
                          </td>
                          <td className="py-2.5 pl-3 text-right">
                            <button
                              type="button"
                              onClick={() =>
                                handleRemediateToggle(
                                  Number(ind.indicator_id),
                                  'OPEN'
                                )
                              }
                              className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md cursor-pointer"
                            >
                              Re-open Finding
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ====================================================================
            VIEW 5: PYTHON 3.11 PROJECT SOURCE CODE & COLLECTOR MODULES
           ==================================================================== */}
        {activeNav === 'python' && (
          <div className="space-y-6">
            <div className="border-b border-slate-200 pb-5">
              <p className="text-xs font-medium text-slate-500">
                Complete Python 3.11 Codebase on Disk
              </p>
              <h1 className="text-2xl font-bold text-slate-900 mt-1">
                Python 3.11 Source Files & Modules
              </h1>
              <p className="text-sm text-slate-600 mt-1">
                All Python modules below are actively executing on the backend with SQLite (`data/risk_scoring.db`) and can also be run directly via{' '}
                <code className="font-mono bg-slate-100 px-1.5 py-0.5 rounded">
                  streamlit run main.py
                </code>{' '}
                or{' '}
                <code className="font-mono bg-slate-100 px-1.5 py-0.5 rounded">
                  python3 main.py --verify
                </code>
                .
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              <div className="bg-white border border-slate-200 rounded-xl p-4 space-y-1 h-fit">
                <div className="text-xs font-semibold text-slate-500 px-2 pb-2">
                  Project Files ({pythonFiles.length})
                </div>
                {pythonFiles.map((f) => (
                  <button
                    key={f.path}
                    type="button"
                    onClick={() => setSelectedPyPath(f.path)}
                    className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono flex items-center gap-2 transition-colors cursor-pointer ${
                      selectedPyPath === f.path
                        ? 'bg-slate-900 text-white font-semibold'
                        : 'text-slate-700 hover:bg-slate-100'
                    }`}
                  >
                    <FileCode2 className="w-3.5 h-3.5 shrink-0" />
                    <span className="truncate">{f.path}</span>
                  </button>
                ))}
              </div>

              <div className="lg:col-span-3 bg-white border border-slate-200 rounded-xl overflow-hidden flex flex-col">
                <div className="px-4 py-3 bg-slate-100 border-b border-slate-200 flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold text-slate-900">
                    {activePyFile.path}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(activePyFile.content);
                      setStatusBanner(`Copied ${activePyFile.path} to clipboard.`);
                    }}
                    className="px-3 py-1 text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-md hover:bg-slate-50 inline-flex items-center gap-1.5 cursor-pointer"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Code</span>
                  </button>
                </div>
                <pre className="p-4 text-xs font-mono text-slate-800 overflow-x-auto max-h-[640px] leading-relaxed">
                  <code>{activePyFile.content}</code>
                </pre>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="bg-white border-t border-slate-200 px-6 py-4 mt-12">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
          <span>
            A Lightweight Cybersecurity Risk Scoring System for SMEs Using Threat Indicators
          </span>
          <span>
            Python 3.11 · SQLite (`data/risk_scoring.db`) · SHA-256 Deduplication
          </span>
        </div>
      </footer>
    </div>
  );
}
