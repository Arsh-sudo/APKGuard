import { APKReport, SystemStats, Job } from '../types';

export const mockReports: APKReport[] = [
  {
    apk_name: 'BankingTrojan-Hydra.apk',
    apk_size_kb: 428.6,
    analysed_at: '2026-05-24T14:28:10Z',
    manifest: {
      package: 'com.sec.auth.hydra.update',
      version_name: '3.4.1',
      version_code: '341',
      min_sdk: 24,
      target_sdk: 33,
      activities_count: 5,
      services_count: 4,
      receivers_count: 6,
      providers_count: 1,
      activities: [
        'com.sec.auth.hydra.MainActivity',
        'com.sec.auth.hydra.OverlayInjectionActivity',
        'com.sec.auth.hydra.FakePasscodeInputActivity',
        'com.sec.auth.hydra.PermissionsRequestProxy',
        'com.sec.auth.hydra.AdminEnablerActivity'
      ],
      services: [
        'com.sec.auth.hydra.CoreAccessibilityService',
        'com.sec.auth.hydra.BackgroundPersistenceDaemon',
        'com.sec.auth.hydra.C2HeartbeatService',
        'com.sec.auth.hydra.SmsSnifferService'
      ],
      receivers: [
        'com.sec.auth.hydra.SmsBroadcastReceiver',
        'com.sec.auth.hydra.BootCompleteReceiver',
        'com.sec.auth.hydra.AdminPolicyReceiver',
        'com.sec.auth.hydra.NetworkStateReceiver',
        'com.sec.auth.hydra.ScreenStateReceiver',
        'com.sec.auth.hydra.PackageReplacedReceiver'
      ],
      dangerous_permissions: [
        'READ_SMS',
        'SEND_SMS',
        'RECEIVE_SMS',
        'SYSTEM_ALERT_WINDOW',
        'BIND_ACCESSIBILITY_SERVICE',
        'BIND_DEVICE_ADMIN',
        'READ_PHONE_STATE',
        'READ_CONTACTS',
        'REQUEST_INSTALL_PACKAGES'
      ],
      permissions: [
        'android.permission.INTERNET',
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.BIND_DEVICE_ADMIN',
        'android.permission.READ_PHONE_STATE',
        'android.permission.READ_CONTACTS',
        'android.permission.REQUEST_INSTALL_PACKAGES',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.WAKE_LOCK',
        'android.permission.ACCESS_NETWORK_STATE'
      ]
    },
    static_analysis: {
      total_java_files: 412,
      hardcoded_urls: [
        'https://gate.darkgate-c2.top/api/v2/handshake',
        'https://sync.stealer-payload.cc/inject/template.json',
        'https://dns.fallback-c2.is/beacon'
      ],
      hardcoded_ips: ['185.244.181.92', '91.108.240.11', '194.87.112.4'],
      suspicious_keywords: {
        AccessibilityService: 8,
        onAccessibilityEvent: 14,
        sendTextMessage: 6,
        SYSTEM_ALERT_WINDOW: 5,
        KeyLogger: 3,
        DevicePolicyManager: 4,
        addJavascriptInterface: 2,
        getRuntime: 7,
        Cipher: 12
      },
      obfuscation_score: 86,
      obfuscation_flag: true,
      native_lib_count: 1,
      native_libs: ['libantivm_unpack.so'],
      dex_count: 2,
      smali_file_count: 640,
      md5: '7d4bf09c0b118b87a93dbce2491a92df',
      sha1: '9c5e3d7a8f11054b12df718bb720c7492c813d90',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    },
    heuristic_scoring: {
      heuristic_score: 98,
      category: 'CRITICAL',
      reasons: [
        'Declares high-risk SMS interceptor triplet (READ_SMS, SEND_SMS, RECEIVE_SMS)',
        'Abuses BIND_ACCESSIBILITY_SERVICE for programmatic touch emulation & keylogging',
        'SYSTEM_ALERT_WINDOW enabled with targeted banking overlay layouts in assets',
        'Heavy ProGuard + custom string encryption detected in Dalvik bytecode',
        'C2 command gate endpoints hardcoded with dynamic fallback resolution'
      ]
    },
    ml_scoring: {
      ml_probability: 0.994,
      ml_score: 99.4,
      heuristic_score: 98,
      final_score: 99.4,
      category: 'CRITICAL',
      model_confidence: 99.2,
      operating_threshold: 0.80,
      top_features: [
        { name: 'perm::BIND_ACCESSIBILITY_SERVICE', importance: 0.94, impact: 'positive', description: 'Allows programmatic UI hijacking and text scraping', value: 1 },
        { name: 'perm::RECEIVE_SMS', importance: 0.89, impact: 'positive', description: 'Intercepts incoming banking OTPs and 2FA challenge tokens', value: 1 },
        { name: 'api::onAccessibilityEvent', importance: 0.86, impact: 'positive', description: 'Monitors user input inside target banking app packages', value: 14 },
        { name: 'perm::SYSTEM_ALERT_WINDOW', importance: 0.82, impact: 'positive', description: 'Injects deceptive overlay windows over authentic banking apps', value: 1 },
        { name: 'api::sendTextMessage', importance: 0.78, impact: 'positive', description: 'Exfiltrates SMS or triggers premium USSD/SMS actions', value: 6 },
        { name: 'str::obfuscation_entropy', importance: 0.74, impact: 'positive', description: 'Dalvik identifier entropy matches commercial packers', value: '86%' },
        { name: 'api::DevicePolicyManager', importance: 0.69, impact: 'positive', description: 'Prevents victim from uninstalling via device administrator hook', value: 4 },
        { name: 'net::hardcoded_ip_ratio', importance: 0.63, impact: 'positive', description: 'Direct IP communication without legitimate CDN/DNS layering', value: 3 },
        { name: 'perm::REQUEST_INSTALL_PACKAGES', importance: 0.58, impact: 'positive', description: 'Secondary payload drop capability', value: 1 },
        { name: 'dex::smali_complexity', importance: 0.52, impact: 'positive', description: 'Reflective classloading with DES/AES string decryptors', value: 640 }
      ]
    },
    llm_analysis: {
      model: 'Llama 3.2 3B (Ollama Local)',
      threat_summary: 'VERDICT: Active Android Banking Trojan belonging to the Hydra/Godfather family.\nTHREAT CLASSIFICATION: High-Priority Credential Harvester & Transaction Tamperer.\nPRIMARY OBJECTIVE: Unauthorized account takeover via 2FA bypass and credential harvesting.\nIMMEDIATE MITIGATION: Enterprise-wide MDM blacklisting and device revocation advised.',
      permission_analysis: 'The application explicitly couples SMS handling permissions with BIND_ACCESSIBILITY_SERVICE. In a financial context, this pairing allows malware to suppress inbound bank notifications while exfiltrating one-time passcodes and granting itself background permissions without user intervention.',
      code_analysis: 'Static bytecode decompilation reveals an event-driven overlay loop. When targeted banking packages (such as Chase, Wells Fargo, or HDFC) transition to the foreground, the malware activates a full-screen SYSTEM_ALERT_WINDOW matching the bank layout to capture login credentials before passing control back to the authentic app.',
      plain_explanation: 'This app is a dangerous banking trojan disguised as an authentication update. Once installed, it steals your bank passwords and intercepts text messages containing security codes, allowing criminals to drain linked accounts.',
      ciso_recommendation: 'Immediate perimeter block of domains and IP endpoints. Alert SOC to search for user sessions displaying device package "com.sec.auth.hydra.update".'
    }
  },
  {
    apk_name: 'QuickCredit-FastLoan.apk',
    apk_size_kb: 1240.2,
    analysed_at: '2026-05-23T19:12:00Z',
    manifest: {
      package: 'in.fastcredit.cashadvance.pro',
      version_name: '2.1.0',
      version_code: '210',
      min_sdk: 26,
      target_sdk: 33,
      activities_count: 8,
      services_count: 2,
      receivers_count: 3,
      providers_count: 1,
      activities: [
        'in.fastcredit.cashadvance.SplashActivity',
        'in.fastcredit.cashadvance.ApplyActivity',
        'in.fastcredit.cashadvance.KYCCameraActivity',
        'in.fastcredit.cashadvance.ContactConsentActivity'
      ],
      services: ['in.fastcredit.cashadvance.TelemetryService'],
      receivers: ['in.fastcredit.cashadvance.SMSReceiver'],
      dangerous_permissions: [
        'READ_CONTACTS',
        'READ_SMS',
        'CAMERA',
        'ACCESS_FINE_LOCATION',
        'READ_CALL_LOG',
        'READ_PHONE_STATE'
      ],
      permissions: [
        'android.permission.INTERNET',
        'android.permission.READ_CONTACTS',
        'android.permission.READ_SMS',
        'android.permission.CAMERA',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_CALL_LOG',
        'android.permission.READ_PHONE_STATE',
        'android.permission.ACCESS_NETWORK_STATE'
      ]
    },
    static_analysis: {
      total_java_files: 580,
      hardcoded_urls: [
        'https://api.loanharvest-collector.xyz/v1/contacts/bulk',
        'https://sync.analytics-datagate.cc/logs'
      ],
      hardcoded_ips: ['103.145.13.88'],
      suspicious_keywords: {
        getSubscriberId: 4,
        getDeviceId: 3,
        HttpURLConnection: 18,
        sendTextMessage: 2,
        Base64: 21
      },
      obfuscation_score: 42,
      obfuscation_flag: false,
      native_lib_count: 0,
      native_libs: [],
      dex_count: 1,
      smali_file_count: 380,
      md5: 'a81bc20173c713b194d6501c5f89a912',
      sha1: '3df87b99c878b271d44ea1b098198f82873c0911',
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    },
    heuristic_scoring: {
      heuristic_score: 84,
      category: 'CRITICAL',
      reasons: [
        'Mass address book exfiltration routine matching predatory loan blackmail apps',
        'Requests full READ_CALL_LOG and READ_SMS without operational financial utility',
        'Hardcoded untrusted TLD endpoint for contact book batch upload'
      ]
    },
    ml_scoring: {
      ml_probability: 0.942,
      ml_score: 94.2,
      heuristic_score: 84,
      final_score: 94.2,
      category: 'CRITICAL',
      model_confidence: 94.8,
      operating_threshold: 0.80,
      top_features: [
        { name: 'perm::READ_CONTACTS', importance: 0.88, impact: 'positive', description: 'Mass harvesting of customer phonebook', value: 1 },
        { name: 'perm::READ_CALL_LOG', importance: 0.82, impact: 'positive', description: 'Surveillance of user communication patterns', value: 1 },
        { name: 'perm::READ_SMS', importance: 0.79, impact: 'positive', description: 'Extracts financial transaction messages and credit balances', value: 1 },
        { name: 'api::getSubscriberId', importance: 0.71, impact: 'positive', description: 'IMSI/hardware fingerprint tracking', value: 4 },
        { name: 'net::bulk_upload_endpoint', importance: 0.65, impact: 'positive', description: 'Batch contact serialization over HTTP', value: 1 },
        { name: 'perm::ACCESS_FINE_LOCATION', importance: 0.58, impact: 'positive', description: 'Continuous location tracking without navigation context', value: 1 }
      ]
    },
    llm_analysis: {
      model: 'Llama 3.2 3B (Ollama Local)',
      threat_summary: 'VERDICT: Predatory Loanware & Extortion Spyware.\nTHREAT CLASSIFICATION: High Risk Privacy Violation & Coercive Data Harvesting.\nPRIMARY OBJECTIVE: Scraping complete personal contact databases and call histories for extortion.',
      permission_analysis: 'The application requests permissions well outside the scope of lending underwriting. Access to full call logs and SMS history is routinely leveraged by unlicensed loan applications to harass relatives and colleagues.',
      code_analysis: 'Source routines show JSON serialization of the device ContactContract content resolver directly piped to unencrypted remote collector endpoints.',
      plain_explanation: 'This app is a predatory loan scam. It secretly copies all contacts, call records, and private messages from your phone and uploads them to an unknown server to threaten or blackmail users.',
      ciso_recommendation: 'Blacklist package on all corporate-managed endpoints and issue employee warning regarding unauthorized loan apps.'
    }
  },
  {
    apk_name: 'HDFC-RewardPoints-Redeem.apk',
    apk_size_kb: 512.8,
    analysed_at: '2026-05-22T09:44:31Z',
    manifest: {
      package: 'org.hdfc.netreward.claim',
      version_name: '1.0.4',
      version_code: '4',
      min_sdk: 23,
      target_sdk: 31,
      activities_count: 3,
      services_count: 1,
      receivers_count: 2,
      providers_count: 0,
      activities: ['org.hdfc.netreward.claim.FormActivity', 'org.hdfc.netreward.claim.OtpActivity'],
      services: ['org.hdfc.netreward.claim.ForwarderService'],
      receivers: ['org.hdfc.netreward.claim.OtpForwarderReceiver'],
      dangerous_permissions: ['RECEIVE_SMS', 'READ_SMS', 'READ_PHONE_STATE'],
      permissions: [
        'android.permission.INTERNET',
        'android.permission.RECEIVE_SMS',
        'android.permission.READ_SMS',
        'android.permission.READ_PHONE_STATE',
        'android.permission.RECEIVE_BOOT_COMPLETED'
      ]
    },
    static_analysis: {
      total_java_files: 94,
      hardcoded_urls: ['http://api.telegram.org/bot684920491:AAH.../sendMessage'],
      hardcoded_ips: ['149.154.167.220'],
      suspicious_keywords: {
        sendTextMessage: 2,
        HttpURLConnection: 6,
        WebView: 2,
        Base64: 4
      },
      obfuscation_score: 30,
      obfuscation_flag: false,
      native_lib_count: 0,
      native_libs: [],
      dex_count: 1,
      smali_file_count: 110,
      md5: 'b10a8db164e0754105b7a99be72e3fe5',
      sha1: '2ef7b78f7e2d93e2b2fe8e90e72e3fe57e2d93e2',
      sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'
    },
    heuristic_scoring: {
      heuristic_score: 76,
      category: 'HIGH_RISK',
      reasons: [
        'Phishing decoy targeting HDFC Bank customers with fake reward redemption forms',
        'Hardcoded Telegram Bot API token used as Command & Control data exfiltration tunnel',
        'Automated SMS receiver forwards OTP tokens to attacker Telegram channel'
      ]
    },
    ml_scoring: {
      ml_probability: 0.785,
      ml_score: 78.5,
      heuristic_score: 76,
      final_score: 78.5,
      category: 'HIGH_RISK',
      model_confidence: 89.4,
      operating_threshold: 0.80,
      top_features: [
        { name: 'perm::RECEIVE_SMS', importance: 0.84, impact: 'positive', description: 'Intercepts incoming banking SMS OTP', value: 1 },
        { name: 'str::telegram_bot_api', importance: 0.81, impact: 'positive', description: 'Exfiltrates captured card CVV & credentials via Telegram bot', value: 1 },
        { name: 'perm::READ_PHONE_STATE', importance: 0.62, impact: 'positive', description: 'Binds victim SIM identifier to stolen credentials', value: 1 }
      ]
    },
    llm_analysis: {
      model: 'Llama 3.2 3B (Ollama Local)',
      threat_summary: 'VERDICT: Phishing Dropper & Telegram OTP Forwarder.\nTHREAT CLASSIFICATION: Targeted Financial Phishing (HDFC Impersonation).\nPRIMARY OBJECTIVE: Steals debit/credit card details, CVV, and intercepts 2FA OTPs.',
      permission_analysis: 'The application requires RECEIVE_SMS to read incoming one-time passwords while displaying a fake "processing reward points" spinner to the user.',
      code_analysis: 'Bytecode directly constructs HTTP POST requests to Telegram Bot API endpoint with formatted payload containing user-submitted card numbers and captured SMS verification codes.',
      plain_explanation: 'This is a fake bank app pretending to give reward points. It tricks you into typing your card number and PIN, then secretly forwards your bank verification codes to a scammer on Telegram.',
      ciso_recommendation: 'Coordinate domain and Telegram bot takedown with telecommunications and security CERT teams.'
    }
  },
  {
    apk_name: 'WhatsApp-Official-v2.24.apk',
    apk_size_kb: 38920.4,
    analysed_at: '2026-05-21T11:02:18Z',
    manifest: {
      package: 'com.whatsapp',
      version_name: '2.24.10.74',
      version_code: '241074001',
      min_sdk: 21,
      target_sdk: 34,
      activities_count: 64,
      services_count: 28,
      receivers_count: 18,
      providers_count: 4,
      activities: ['com.whatsapp.HomeActivity', 'com.whatsapp.Conversation', 'com.whatsapp.camera.CameraActivity'],
      services: ['com.whatsapp.messaging.MessageService', 'com.whatsapp.backup.google.GoogleBackupService'],
      receivers: ['com.whatsapp.gcm.RegistrationIntentService$RegistrationReceiver'],
      dangerous_permissions: [
        'CAMERA',
        'RECORD_AUDIO',
        'READ_CONTACTS',
        'WRITE_CONTACTS',
        'ACCESS_FINE_LOCATION'
      ],
      permissions: [
        'android.permission.INTERNET',
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.VIBRATE',
        'android.permission.WAKE_LOCK'
      ]
    },
    static_analysis: {
      total_java_files: 14200,
      hardcoded_urls: ['https://graph.whatsapp.net', 'https://v.whatsapp.net/v2'],
      hardcoded_ips: [],
      suspicious_keywords: {
        Cipher: 48,
        Base64: 34,
        AES: 22,
        HttpURLConnection: 12
      },
      obfuscation_score: 18,
      obfuscation_flag: false,
      native_lib_count: 8,
      native_libs: ['libwhatsapp.so', 'libopus.so', 'libvpx.so'],
      dex_count: 4,
      smali_file_count: 8200,
      md5: 'ef2d127de37b942baad06145e54b0c61',
      sha1: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
      sha256: '88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
    },
    heuristic_scoring: {
      heuristic_score: 18,
      category: 'LOW_RISK',
      reasons: [
        'Legitimate communications application with valid official certificates',
        'Permissions align directly with declared user messaging and VOIP capabilities',
        'No deceptive overlay or accessibility service misuse detected'
      ]
    },
    ml_scoring: {
      ml_probability: 0.142,
      ml_score: 14.2,
      heuristic_score: 18,
      final_score: 14.2,
      category: 'LOW_RISK',
      model_confidence: 97.5,
      operating_threshold: 0.80,
      top_features: [
        { name: 'perm::BIND_ACCESSIBILITY_SERVICE', importance: 0.95, impact: 'negative', description: 'Absent — no accessibility UI abuse', value: 0 },
        { name: 'perm::READ_SMS', importance: 0.91, impact: 'negative', description: 'Absent — does not sniff SMS messages', value: 0 },
        { name: 'perm::SYSTEM_ALERT_WINDOW', importance: 0.88, impact: 'negative', description: 'Absent — no deceptive screen overlays', value: 0 },
        { name: 'model::verified_developer_profile', importance: 0.74, impact: 'negative', description: 'Consistent Meta/WhatsApp signing keystore', value: 1 }
      ]
    },
    llm_analysis: {
      model: 'Llama 3.2 3B (Ollama Local)',
      threat_summary: 'VERDICT: Clean and Legitimate Communication Software.\nTHREAT CLASSIFICATION: Benign Commercial Application.\nPRIMARY OBJECTIVE: Instant messaging, voice calling, and encrypted communication.',
      permission_analysis: 'Declared permissions (Camera, Microphone, Contacts) are standard requirements for interactive video/audio chat and contact synchronisation. The package does not seek SMS interception or device admin controls.',
      code_analysis: 'Cryptographic routines (AES, Cipher) correspond to end-to-end Signal Protocol implementations. Network traffic routes exclusively to official verified endpoints.',
      plain_explanation: 'This is the official WhatsApp application. It is safe and does not contain malicious code or banking threat behaviors.',
      ciso_recommendation: 'No action required. Allow package execution in line with corporate BYOD messaging guidelines.'
    }
  },
  {
    apk_name: 'GoogleCalculator-v8.1.apk',
    apk_size_kb: 6571.1,
    analysed_at: '2026-05-20T22:19:42Z',
    manifest: {
      package: 'com.google.android.calculator',
      version_name: '8.1',
      version_code: '81001',
      min_sdk: 23,
      target_sdk: 33,
      activities_count: 2,
      services_count: 0,
      receivers_count: 1,
      providers_count: 0,
      activities: ['com.android.calculator2.Calculator'],
      services: [],
      receivers: ['com.android.calculator2.CalculatorWidgetProvider'],
      dangerous_permissions: [],
      permissions: ['android.permission.INTERNET', 'android.permission.WAKE_LOCK']
    },
    static_analysis: {
      total_java_files: 3538,
      hardcoded_urls: [],
      hardcoded_ips: [],
      suspicious_keywords: { Base64: 8, DES: 2, getRuntime: 1 },
      obfuscation_score: 12,
      obfuscation_flag: false,
      native_lib_count: 2,
      native_libs: ['libcalculator.so', 'libmath.so'],
      dex_count: 2,
      smali_file_count: 240,
      md5: '5d41402abc4b2a76b9719d911017c592',
      sha1: '7b52009b64fd0a2a49e6d8a939753077792b0554',
      sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
    },
    heuristic_scoring: {
      heuristic_score: 4,
      category: 'LOW_RISK',
      reasons: [
        'Zero dangerous permissions declared in AndroidManifest.xml',
        'Official Google application signing footprint',
        'Minimal surface area: single core activity, zero suspicious receivers'
      ]
    },
    ml_scoring: {
      ml_probability: 0.041,
      ml_score: 4.1,
      heuristic_score: 4,
      final_score: 4.1,
      category: 'LOW_RISK',
      model_confidence: 99.8,
      operating_threshold: 0.80,
      top_features: [
        { name: 'perm::dangerous_count', importance: 0.98, impact: 'negative', description: 'Zero dangerous Android permissions', value: 0 },
        { name: 'perm::READ_SMS', importance: 0.92, impact: 'negative', description: 'Absent', value: 0 },
        { name: 'perm::SYSTEM_ALERT_WINDOW', importance: 0.89, impact: 'negative', description: 'Absent', value: 0 },
        { name: 'api::onAccessibilityEvent', importance: 0.85, impact: 'negative', description: 'Zero accessibility hooks', value: 0 }
      ]
    },
    llm_analysis: {
      model: 'Llama 3.2 3B (Ollama Local)',
      threat_summary: 'VERDICT: Clean, Benign System Utility.\nTHREAT CLASSIFICATION: Non-Threatening Calculator Application.\nPRIMARY OBJECTIVE: Standard mathematical calculations and currency conversions.',
      permission_analysis: 'The application contains zero dangerous permissions. It cannot access SMS, camera, location, or file system assets outside its sandbox.',
      code_analysis: 'Dalvik bytecode contains only standard math formatting libraries and Android Jetpack UI components. Zero network beaconing or obfuscation triggers.',
      plain_explanation: 'This is the official Google Calculator app. It is completely safe to install and use.',
      ciso_recommendation: 'Approved for universal deployment across all enterprise environments.'
    }
  }
];

export const mockStats: SystemStats = {
  total: 428,
  critical: 164,
  high_risk: 72,
  suspicious: 38,
  low_risk: 154,
  avg_score: 54.8,
  with_llm: 396,
  weekly_trend: [38, 45, 52, 60, 58, 67, 74]
};

export const bentoBenchmarkData = {
  rocAuc: 0.971,
  f1Score: 0.926,
  totalSamples: 398,
  totalFeatures: 330,
  operatingThreshold: 0.80,
  thresholdTable: [
    { threshold: 0.50, precision: 0.884, recall: 0.952, f1: 0.917, fpr: '6.2%' },
    { threshold: 0.70, precision: 0.921, recall: 0.938, f1: 0.929, fpr: '3.8%' },
    { threshold: 0.80, precision: 0.962, recall: 0.894, f1: 0.926, fpr: '1.4%' },
    { threshold: 0.90, precision: 0.988, recall: 0.812, f1: 0.891, fpr: '0.4%' }
  ],
  prevalenceData: [
    { prevalence: '50% (Lab Dataset)', precision: 96.2, recall: 89.4, falsePositives: 14 },
    { prevalence: '10% (High Risk Stream)', precision: 87.5, recall: 89.4, falsePositives: 38 },
    { prevalence: '1% (Enterprise BYOD)', precision: 41.2, recall: 89.4, falsePositives: 140 },
    { prevalence: '0.1% (General App Store)', precision: 6.8, recall: 89.4, falsePositives: 1400 }
  ]
};

export const mockRecentLogs = [
  '[14:28:10] [DECOMPILE] Unpacking BankingTrojan-Hydra.apk via apktool v2.9.3...',
  '[14:28:12] [DEX] Extracted 2 Dalvik executables (classes.dex, classes2.dex)',
  '[14:28:13] [MANIFEST] Identified 9 dangerous permissions: READ_SMS, BIND_ACCESSIBILITY_SERVICE...',
  '[14:28:14] [XGBOOST] Extracted 330 features across permission & bytecode matrix',
  '[14:28:15] [XGBOOST] Inference completed: 99.4/100 risk probability (Verdict: CRITICAL)',
  '[14:28:16] [OLLAMA] Streaming structured explanation from Llama-3.2-3B...',
  '[14:28:18] [VERDICT] Pipeline completed in 8.2s. Report cached with SHA256: e3b0c442...'
];
