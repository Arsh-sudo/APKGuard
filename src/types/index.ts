export type VerdictCategory = 'CRITICAL' | 'HIGH_RISK' | 'SUSPICIOUS' | 'LOW_RISK' | 'UNKNOWN';

export type JobStatus = 'queued' | 'running' | 'done' | 'error' | 'cancelled';

export interface ManifestData {
  package: string;
  version_name: string;
  version_code: string;
  min_sdk?: number;
  target_sdk?: number;
  permissions: string[];
  dangerous_permissions: string[];
  activities_count: number;
  services_count: number;
  receivers_count: number;
  providers_count: number;
  activities: string[];
  services: string[];
  receivers: string[];
  providers?: string[];
}

export interface StaticAnalysis {
  total_java_files: number;
  hardcoded_urls: string[];
  hardcoded_ips: string[];
  suspicious_keywords: Record<string, number>;
  obfuscation_score: number;
  obfuscation_flag: boolean;
  native_lib_count: number;
  native_libs: string[];
  dex_count: number;
  smali_file_count: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
}

export interface HeuristicScoring {
  heuristic_score: number;
  score?: number;
  category: VerdictCategory;
  reasons: string[];
}

export interface XGBoostFeature {
  name: string;
  importance: number; // 0 to 1
  impact: 'positive' | 'negative' | 'neutral';
  description: string;
  value: string | number;
  present?: boolean;
}

export interface MLScoring {
  ml_probability: number;
  ml_score: number;
  heuristic_score: number;
  final_score: number;
  category: VerdictCategory;
  model_confidence?: number;
  top_features?: XGBoostFeature[];
  operating_threshold?: number;
}

export interface LLMAnalysis {
  model: string;
  threat_summary: string;
  permission_analysis: string;
  code_analysis: string;
  plain_explanation: string;
  generated_at?: string;
  ciso_recommendation?: string;
  executive_summary?: string;
  threat_mechanism?: string;
  plain_english_advisory?: string;
  high_risk_permissions_context?: { permission: string; context: string }[];
  recommendations?: string[];
  evasion_techniques?: string[];
}

export interface APKReport {
  apk_name: string;
  apk_size_kb: number;
  analysed_at: string;
  manifest: ManifestData;
  static_analysis: StaticAnalysis;
  heuristic_scoring: HeuristicScoring;
  ml_scoring: MLScoring;
  llm_analysis: LLMAnalysis | null;
}

export interface Job {
  job_id: string;
  apk_name: string;
  original_name: string;
  status: JobStatus;
  progress: number;
  current_step: number; // 1: Upload & Validate, 2: Decompile, 3: ML Inference, 4: LLM Explanation
  message: string;
  logs: string[];
  result: APKReport | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export type AnalysisJob = Job;

export interface SystemStats {
  total: number;
  critical: number;
  high_risk: number;
  suspicious: number;
  low_risk: number;
  avg_score: number;
  with_llm: number;
  weekly_trend?: number[];
}

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message?: string;
  duration?: number;
  action?: {
    label: string;
    onClick: () => void;
  };
}
