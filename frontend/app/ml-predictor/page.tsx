"use client";

import * as React from "react";
import { AppLayout, TopBar, Card, Button, Input } from "@/components/cyber";
import { API_URL } from "@/lib/config";
import { Brain, RefreshCw, ChevronDown, ChevronUp, Info, ShieldCheck, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────

interface FeatureItem {
  name: string;
  value: number;
  importance?: number;
  contribution?: string;
  description?: string;
}

interface FeatureImportance {
  feature: string;
  importance: number;
}

interface MLResult {
  model?: string;
  model_version?: string;
  task?: string;
  prediction?: string;
  score?: number;
  score_type?: string;
  risk_level?: string;
  label: string;
  confidence: number;
  confidence_pct: number;
  explanation: string;
  features?: FeatureItem[];
  feature_importances: FeatureImportance[];
  model_name: string;
  raw_scores?: Record<string, any>;
}

// ── Helpers ───────────────────────────────────────────────────────────────

function getLabelColor(label: string) {
  const danger = ["PHISHING", "FRAUDULENT", "ANOMALOUS"];
  const warn = ["SUSPICIOUS"];
  if (danger.includes(label)) return "text-risk-critical bg-risk-critical-dim";
  if (warn.includes(label)) return "text-risk-moderate bg-risk-moderate-dim";
  return "text-risk-safe bg-risk-safe-dim";
}

function getBarColor(pct: number) {
  if (pct >= 70) return "bg-risk-critical";
  if (pct >= 40) return "bg-risk-moderate";
  return "bg-risk-safe";
}

// ── Sub-components ────────────────────────────────────────────────────────

function ScoreBar({ pct, scoreType }: { pct: number; scoreType?: string }) {
  const label = scoreType === "anomaly_score" ? "Anomaly Score" : "Probability / Confidence";
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-[11px]">
        <span className="text-text-muted font-semibold uppercase tracking-wider">{label}</span>
        <span className="font-bold text-text-primary">{pct}%</span>
      </div>
      <div className="h-2.5 w-full rounded-full bg-border overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all duration-700", getBarColor(pct))}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function FeatureChart({ features }: { features: FeatureImportance[] }) {
  const maxImp = features[0]?.importance || 1;
  return (
    <div className="space-y-2">
      <p className="text-[10px] font-bold uppercase tracking-wider text-text-muted">
        Model Feature Importances (Tree Splits)
      </p>
      {features.slice(0, 6).map((fi) => {
        const pct = Math.round((fi.importance / maxImp) * 100);
        return (
          <div key={fi.feature} className="flex items-center gap-3">
            <span className="w-40 shrink-0 font-mono text-[11px] text-text-secondary truncate">{fi.feature}</span>
            <div className="flex-1 h-2 rounded-full bg-border overflow-hidden">
              <div className="h-full rounded-full bg-primary/70" style={{ width: `${pct}%` }} />
            </div>
            <span className="w-12 text-right font-mono text-[11px] text-text-muted">
              {(fi.importance * 100).toFixed(1)}%
            </span>
          </div>
        );
      })}
    </div>
  );
}

function MLResultPanel({ result }: { result: MLResult }) {
  const [expanded, setExpanded] = React.useState(true);
  const isAnomaly = result.score_type === "anomaly_score" || result.model_name.includes("Isolation");

  return (
    <div className="rounded-xl border border-primary/30 bg-primary-dim/10 p-5 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Brain className="h-5 w-5 text-primary" />
          <div>
            <p className="text-[10px] font-mono uppercase tracking-wider text-text-muted">{result.model_name}</p>
            <span
              className={cn(
                "mt-0.5 inline-flex rounded-full px-3 py-0.5 text-[11px] font-bold uppercase tracking-wider",
                getLabelColor(result.prediction || result.label)
              )}
            >
              {result.prediction || result.label}
            </span>
          </div>
        </div>
        <button
          onClick={() => setExpanded((v) => !v)}
          className="text-text-muted hover:text-text-primary transition-colors"
        >
          {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </button>
      </div>

      {expanded && (
        <>
          <ScoreBar pct={result.confidence_pct} scoreType={result.score_type} />

          {/* Explanation */}
          <div className="rounded-lg border-l-2 border-primary bg-primary-dim/30 px-4 py-3">
            <p className="text-[13px] text-text-primary leading-relaxed">{result.explanation}</p>
          </div>

          {/* Signals vs Importances */}
          {isAnomaly ? (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-text-muted mb-2">
                Contributing Signals & Risk Indicators
              </p>
              <div className="space-y-1.5 divide-y divide-border/20">
                {(result.features || []).map((f) => (
                  <div key={f.name} className="pt-1.5 flex items-center justify-between text-xs">
                    <div>
                      <span className="font-mono text-text-primary">{f.name}</span>
                      {f.description && <p className="text-[10px] text-text-muted">{f.description}</p>}
                    </div>
                    <span className={cn(
                      "font-bold text-[10px] px-2 py-0.5 rounded",
                      f.value > 0 ? "bg-risk-critical/10 text-risk-critical" : "bg-border text-text-muted"
                    )}>
                      {f.value > 0 ? "ACTIVE" : "INACTIVE"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            result.feature_importances && result.feature_importances.length > 0 && (
              <FeatureChart features={result.feature_importances} />
            )
          )}

          {/* Raw scores */}
          {result.raw_scores && Object.keys(result.raw_scores).length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-2">Raw Model Scores</p>
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.raw_scores).map(([k, v]) => (
                  <span key={k} className="rounded-md border border-border bg-bg-card px-2.5 py-1 font-mono text-[11px] text-text-secondary">
                    {k}: {typeof v === "number" ? v.toFixed(3) : String(v)}
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Tab content ────────────────────────────────────────────────────────────

function PhishingTab({ token }: { token: string }) {
  const [form, setForm] = React.useState({
    spf_fail: "0",
    dkim_fail: "0",
    dmarc_fail: "0",
    domain_mismatch: "0",
    spoofed: "0",
    reply_to_mismatch: "0",
  });
  const [result, setResult] = React.useState<MLResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const toggle = (key: string) =>
    setForm((prev) => ({ ...prev, [key]: prev[key as keyof typeof prev] === "0" ? "1" : "0" }));

  const loadDemo = (type: "phishing" | "clean") => {
    if (type === "phishing") {
      setForm({
        spf_fail: "1",
        dkim_fail: "1",
        dmarc_fail: "1",
        domain_mismatch: "1",
        spoofed: "1",
        reply_to_mismatch: "1",
      });
    } else {
      setForm({
        spf_fail: "0",
        dkim_fail: "0",
        dmarc_fail: "0",
        domain_mismatch: "0",
        spoofed: "0",
        reply_to_mismatch: "0",
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API_URL}/api/ml/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          scan_type: "phishing_email",
          features: Object.fromEntries(Object.entries(form).map(([k, v]) => [k, Number(v)])),
        }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Prediction failed");
      setResult(await res.json());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fields = [
    { key: "spf_fail", label: "SPF Fail", hint: "SPF authentication failure" },
    { key: "dkim_fail", label: "DKIM Fail", hint: "DKIM cryptographic signature failure" },
    { key: "dmarc_fail", label: "DMARC Fail", hint: "DMARC alignment policy failure" },
    { key: "domain_mismatch", label: "Domain Mismatch", hint: "From domain != sending envelope domain" },
    { key: "spoofed", label: "Spoofed Brand", hint: "Known brand impersonation flag" },
    { key: "reply_to_mismatch", label: "Reply-To Mismatch", hint: "Reply-To differs from From domain" },
  ];

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-muted">
          Toggle header indicators to evaluate with the <span className="font-semibold text-primary">RandomForest Classifier</span>.
        </p>
        <div className="flex gap-2 text-xs">
          <button
            type="button"
            onClick={() => loadDemo("phishing")}
            className="text-primary hover:underline font-semibold"
          >
            ⚡ Demo Phishing
          </button>
          <span>·</span>
          <button
            type="button"
            onClick={() => loadDemo("clean")}
            className="text-text-secondary hover:underline"
          >
            Demo Clean
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {fields.map(({ key, label, hint }) => (
          <button
            key={key}
            type="button"
            onClick={() => toggle(key)}
            className={cn(
              "flex items-center justify-between rounded-lg border px-4 py-3 text-left transition-all",
              form[key as keyof typeof form] === "1"
                ? "border-risk-critical bg-risk-critical-dim text-risk-critical"
                : "border-border bg-bg-card text-text-secondary hover:border-primary/30"
            )}
          >
            <div>
              <p className="text-[13px] font-semibold">{label}</p>
              <p className="text-[11px] text-text-muted mt-0.5">{hint}</p>
            </div>
            <span className={cn(
              "ml-3 h-5 w-5 rounded-full border-2 flex-shrink-0 flex items-center justify-center text-[10px] font-bold",
              form[key as keyof typeof form] === "1"
                ? "border-risk-critical bg-risk-critical text-white"
                : "border-border bg-transparent"
            )}>
              {form[key as keyof typeof form] === "1" ? "✓" : ""}
            </span>
          </button>
        ))}
      </div>
      <Button type="submit" disabled={loading} fullWidth>
        {loading ? <><RefreshCw className="h-4 w-4 animate-spin mr-2" />Running Inference…</> : "Run RandomForest Prediction"}
      </Button>
      {error && <p className="text-sm text-risk-critical">{error}</p>}
      {result && <MLResultPanel result={result} />}
    </form>
  );
}

function UpiTab({ token }: { token: string }) {
  const [upiId, setUpiId] = React.useState("");
  const [result, setResult] = React.useState<MLResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!upiId.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API_URL}/api/ml/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ scan_type: "upi", features: { upi_id: upiId.trim() } }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Prediction failed");
      setResult(await res.json());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-muted">
          Analyze UPI handles using the <span className="font-semibold text-primary">GradientBoosting Scorer</span>.
        </p>
        <div className="flex gap-2 text-xs">
          <button
            type="button"
            onClick={() => setUpiId("fake-kyc-refund99283@paytm")}
            className="text-primary hover:underline font-semibold"
          >
            ⚡ Demo Fraud
          </button>
          <span>·</span>
          <button
            type="button"
            onClick={() => setUpiId("legitimateuser@okhdfcbank")}
            className="text-text-secondary hover:underline"
          >
            Demo Safe
          </button>
        </div>
      </div>

      <div>
        <label className="block text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1.5">
          UPI Handle
        </label>
        <Input
          type="text"
          placeholder="e.g. merchant@paytm, fake.fraud@upi"
          value={upiId}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUpiId(e.target.value)}
        />
      </div>
      <Button type="submit" disabled={loading || !upiId.trim()} fullWidth>
        {loading ? <><RefreshCw className="h-4 w-4 animate-spin mr-2" />Running Inference…</> : "Run GradientBoosting Prediction"}
      </Button>
      {error && <p className="text-sm text-risk-critical">{error}</p>}
      {result && <MLResultPanel result={result} />}
    </form>
  );
}

function NetworkTab({ token }: { token: string }) {
  const [form, setForm] = React.useState({
    num_open_ports: "2",
    has_critical: "0",
    has_rdp: "0",
    has_smb: "0",
    has_db: "0",
    has_ftp: "0",
    has_telnet: "0",
  });
  const [result, setResult] = React.useState<MLResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const toggleBool = (key: string) =>
    setForm((prev) => ({ ...prev, [key]: prev[key as keyof typeof prev] === "0" ? "1" : "0" }));

  const loadDemo = (type: "anomalous" | "normal") => {
    if (type === "anomalous") {
      setForm({
        num_open_ports: "6",
        has_critical: "1",
        has_rdp: "1",
        has_smb: "1",
        has_db: "1",
        has_ftp: "1",
        has_telnet: "1",
      });
    } else {
      setForm({
        num_open_ports: "2",
        has_critical: "0",
        has_rdp: "0",
        has_smb: "0",
        has_db: "0",
        has_ftp: "0",
        has_telnet: "0",
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API_URL}/api/ml/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          scan_type: "network",
          features: Object.fromEntries(Object.entries(form).map(([k, v]) => [k, Number(v)])),
        }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "Prediction failed");
      setResult(await res.json());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const boolFields = [
    { key: "has_critical", label: "Critical Port Open", hint: "Telnet / SMB / RDP / Database" },
    { key: "has_rdp", label: "RDP (3389)", hint: "Remote Desktop Protocol exposed" },
    { key: "has_smb", label: "SMB (445)", hint: "Server Message Block exposed (WannaCry vector)" },
    { key: "has_db", label: "MySQL (3306)", hint: "Relational database exposed publicly" },
    { key: "has_ftp", label: "FTP (21)", hint: "Unencrypted file transfer" },
    { key: "has_telnet", label: "Telnet (23)", hint: "Unencrypted remote management" },
  ];

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-text-muted">
          Unsupervised host profiling via <span className="font-semibold text-primary">IsolationForest</span>.
        </p>
        <div className="flex gap-2 text-xs">
          <button
            type="button"
            onClick={() => loadDemo("anomalous")}
            className="text-primary hover:underline font-semibold"
          >
            ⚡ Demo Anomaly
          </button>
          <span>·</span>
          <button
            type="button"
            onClick={() => loadDemo("normal")}
            className="text-text-secondary hover:underline"
          >
            Demo Normal
          </button>
        </div>
      </div>

      <div>
        <label className="block text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1.5">
          Number of Open Ports
        </label>
        <input
          type="number"
          min={0}
          max={50}
          value={form.num_open_ports}
          onChange={(e) => setForm((prev) => ({ ...prev, num_open_ports: e.target.value }))}
          className="w-full rounded-lg border border-border bg-bg-main py-2 px-3 text-sm text-text-primary focus:border-primary focus:outline-none"
        />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {boolFields.map(({ key, label, hint }) => (
          <button
            key={key}
            type="button"
            onClick={() => toggleBool(key)}
            className={cn(
              "flex items-center justify-between rounded-lg border px-4 py-3 text-left transition-all",
              form[key as keyof typeof form] === "1"
                ? "border-risk-critical bg-risk-critical-dim text-risk-critical"
                : "border-border bg-bg-card text-text-secondary hover:border-primary/30"
            )}
          >
            <div>
              <p className="text-[13px] font-semibold">{label}</p>
              <p className="text-[11px] text-text-muted mt-0.5">{hint}</p>
            </div>
            <span className={cn(
              "ml-3 h-5 w-5 rounded-full border-2 flex-shrink-0 flex items-center justify-center text-[10px] font-bold",
              form[key as keyof typeof form] === "1"
                ? "border-risk-critical bg-risk-critical text-white"
                : "border-border bg-transparent"
            )}>
              {form[key as keyof typeof form] === "1" ? "✓" : ""}
            </span>
          </button>
        ))}
      </div>

      <Button type="submit" disabled={loading} fullWidth>
        {loading ? <><RefreshCw className="h-4 w-4 animate-spin mr-2" />Running Inference…</> : "Run IsolationForest Prediction"}
      </Button>
      {error && <p className="text-sm text-risk-critical">{error}</p>}
      {result && <MLResultPanel result={result} />}
    </form>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────

const TABS = [
  { id: "phishing", label: "📧 Email Phishing", desc: "RandomForest Classifier" },
  { id: "upi", label: "💳 UPI Fraud", desc: "GradientBoosting Scorer" },
  { id: "network", label: "🌐 Network Anomaly", desc: "IsolationForest Detector" },
];

export default function MLPredictorPage() {
  const [activeTab, setActiveTab] = React.useState("phishing");
  const [token, setToken] = React.useState("");
  const [user, setUser] = React.useState("");

  React.useEffect(() => {
    // Read from standard cyberguard-token with fallback to legacy token
    const t = localStorage.getItem("cyberguard-token") || localStorage.getItem("token") || "";
    const u = localStorage.getItem("cyberguard-user") || localStorage.getItem("userEmail") || "";
    setToken(t);
    try {
      const parsed = JSON.parse(u);
      setUser(parsed.email || u);
    } catch {
      setUser(u);
    }
  }, []);

  const handleSignOut = () => {
    localStorage.clear();
    sessionStorage.clear();
    window.location.href = "/login";
  };

  return (
    <AppLayout sidebar={{ onSignOut: handleSignOut }}>
      <TopBar title="ML Threat Predictor" userEmail={user} />

      <div className="mx-auto max-w-3xl space-y-6 px-4 py-8">
        {/* Hero */}
        <div className="rounded-2xl border border-primary/20 bg-primary-dim/10 px-6 py-5 flex gap-4 items-start">
          <Brain className="h-8 w-8 text-primary flex-shrink-0 mt-0.5" />
          <div>
            <h2 className="font-display text-lg font-bold text-text-primary">Machine Learning Threat Analysis</h2>
            <p className="mt-1 text-[13px] text-text-muted leading-relaxed">
              Real-time inference using local scikit-learn models. Supervised models report calibrated prediction probabilities and true feature importances; unsupervised anomaly detectors report anomaly scores and active risk indicators.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <span className="rounded-full border border-border px-2.5 py-1 font-mono text-[10px] text-text-muted">RandomForest (Supervised)</span>
              <span className="rounded-full border border-border px-2.5 py-1 font-mono text-[10px] text-text-muted">GradientBoosting (Supervised)</span>
              <span className="rounded-full border border-border px-2.5 py-1 font-mono text-[10px] text-text-muted">IsolationForest (Unsupervised)</span>
              <span className="rounded-full border border-border px-2.5 py-1 font-mono text-[10px] text-text-muted">scikit-learn 1.9</span>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 rounded-xl border border-border bg-bg-card p-1">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex-1 rounded-lg py-2.5 px-3 text-center transition-all",
                activeTab === tab.id
                  ? "bg-primary text-bg-main font-semibold shadow"
                  : "text-text-muted hover:text-text-primary"
              )}
            >
              <p className="text-[12px] font-bold">{tab.label}</p>
              <p className={cn("text-[10px] mt-0.5", activeTab === tab.id ? "text-bg-main/70" : "text-text-muted")}>{tab.desc}</p>
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <Card className="p-6">
          {!token ? (
            <div className="text-center py-8">
              <p className="text-text-muted text-sm">Please log in to execute ML inferences.</p>
              <Button className="mt-4" onClick={() => (window.location.href = "/login")}>Go to Login</Button>
            </div>
          ) : (
            <>
              {activeTab === "phishing" && <PhishingTab token={token} />}
              {activeTab === "upi" && <UpiTab token={token} />}
              {activeTab === "network" && <NetworkTab token={token} />}
            </>
          )}
        </Card>

        {/* Info footer */}
        <div className="flex gap-2 text-[11px] text-text-muted rounded-lg border border-border bg-bg-card px-4 py-3">
          <Info className="h-4 w-4 flex-shrink-0 mt-0.5 text-primary" />
          <p>
            <strong className="text-text-secondary">Methodological Note:</strong> Models are trained on a synthetic baseline dataset for pipeline verification. All predictions are non-blocking and explainable through genuine model parameters.
          </p>
        </div>
      </div>
    </AppLayout>
  );
}
