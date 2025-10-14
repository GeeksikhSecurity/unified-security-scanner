/**
 * Custom Security Rules Implementation
 * Based on Security Testing Checklist: Claude Code & AWS Q Developer
 */

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe?: string;
  languages: string[];
  patterns: RegExp[];
  customLogic?: (code: string, context: any) => boolean;
}

/**
 * Comprehensive Base Security Policy
 */
export const BASE_SECURITY_POLICY = `
Perform a comprehensive scan to identify both security vulnerabilities 
and critical non-security bugs.

SECURITY VULNERABILITIES:
- Language-specific issues and insecure coding practices
- Improper handling of parameters, variables, and data flows
- Trace all user-controlled input to sensitive operations
- Identify missing input validation, sanitization, or encoding
- Check for broken authentication/authorization controls
- Find insecure cryptographic implementations
- Detect unsafe deserialization patterns
- Identify injection vulnerabilities (SQL, command, LDAP, etc.)

NON-SECURITY BUGS (Critical Only):
- Application crashes, severe malfunctions, or instability
- Null pointer dereferences and unhandled exceptions
- Memory leaks in long-running processes
- Use-after-free vulnerabilities
- Undefined behavior in C/C++ code
- Resource leaks in daemon processes
- Deadlocks and race conditions

INTENT ANALYSIS:
- Compare developer comments/documentation with actual code behavior
- Flag mismatches between function names and implementations
- Identify violations of stated specs/RFCs
- Report incorrect exception handling patterns
- Detect logic that contradicts stated purpose

For each language/framework, apply specific vulnerability checks.
Trace parameters and variables throughout code.
Assign CWE IDs and severity levels to all findings.
`;

/**
 * Language-Specific Security Rules
 */
export const JAVASCRIPT_TYPESCRIPT_RULES: SecurityRule[] = [
  {
    id: 'js-prototype-pollution',
    name: 'Prototype Pollution Detection',
    description: 'Detects prototype pollution via __proto__, constructor.prototype, Object.prototype',
    severity: 'HIGH',
    cwe: 'CWE-1321',
    languages: ['javascript', 'typescript'],
    patterns: [
      /__proto__\s*=/,
      /constructor\.prototype\s*=/,
      /Object\.prototype\s*=/,
      /\[\s*['"]__proto__['"]\s*\]/,
    ],
  },
  {
    id: 'js-redos-vulnerability',
    name: 'ReDoS in Regular Expressions',
    description: 'Detects ReDoS in complex regular expressions with nested quantifiers',
    severity: 'MEDIUM',
    cwe: 'CWE-1333',
    languages: ['javascript', 'typescript'],
    patterns: [
      /new RegExp\([^)]*\([^)]*\+[^)]*\)[^)]*\+/,
      /\/[^\/]*\([^\/]*\+[^\/]*\)[^\/]*\+[^\/]*\//,
    ],
  },
  {
    id: 'js-client-side-injection',
    name: 'Client-Side Code Injection',
    description: 'Detects client-side code injection via innerHTML, eval, Function constructor',
    severity: 'CRITICAL',
    cwe: 'CWE-79',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\.innerHTML\s*=\s*[^;]*\+/,
      /eval\s*\(/,
      /new Function\s*\(/,
      /setTimeout\s*\(\s*[^,)]*\+/,
      /setInterval\s*\(\s*[^,)]*\+/,
    ],
  },
  {
    id: 'js-insecure-jwt',
    name: 'Insecure JWT Validation',
    description: 'Detects insecure JWT validation (algorithm confusion, missing signature verification)',
    severity: 'HIGH',
    cwe: 'CWE-347',
    languages: ['javascript', 'typescript'],
    patterns: [
      /jwt\.verify\([^,)]*,\s*null/,
      /jwt\.decode\([^,)]*,\s*{[^}]*verify:\s*false/,
      /algorithm:\s*['"]none['"]/,
    ],
  },
  {
    id: 'js-missing-csrf',
    name: 'Missing CSRF Protection',
    description: 'Detects missing CSRF protection in state-changing operations',
    severity: 'MEDIUM',
    cwe: 'CWE-352',
    languages: ['javascript', 'typescript'],
    patterns: [
      /app\.post\([^,)]*,\s*(?!.*csrf)/,
      /app\.put\([^,)]*,\s*(?!.*csrf)/,
      /app\.delete\([^,)]*,\s*(?!.*csrf)/,
    ],
  },
  {
    id: 'react-dangerous-html',
    name: 'Unsafe dangerouslySetInnerHTML',
    description: 'Detects unsafe use of dangerouslySetInnerHTML in React',
    severity: 'HIGH',
    cwe: 'CWE-79',
    languages: ['javascript', 'typescript'],
    patterns: [
      /dangerouslySetInnerHTML\s*=\s*{{\s*__html:\s*[^}]*\+/,
      /dangerouslySetInnerHTML\s*=\s*{{\s*__html:\s*[^}]*\$\{/,
    ],
  },
];

export const PYTHON_RULES: SecurityRule[] = [
  {
    id: 'py-pickle-deserialization',
    name: 'Pickle Deserialization Vulnerability',
    description: 'Detects pickle deserialization vulnerabilities (use of pickle.loads on untrusted data)',
    severity: 'CRITICAL',
    cwe: 'CWE-502',
    languages: ['python'],
    patterns: [
      /pickle\.loads\s*\(/,
      /cPickle\.loads\s*\(/,
      /pickle\.load\s*\(\s*(?!.*trusted)/,
    ],
  },
  {
    id: 'py-sql-injection',
    name: 'SQL Injection via String Operations',
    description: 'Detects SQL injection via string concatenation or format strings',
    severity: 'CRITICAL',
    cwe: 'CWE-89',
    languages: ['python'],
    patterns: [
      /execute\s*\(\s*[^,)]*\s*\+\s*[^,)]*\)/,
      /execute\s*\(\s*f?['"][^'"]*{[^}]*}[^'"]*['"]\s*\)/,
      /execute\s*\(\s*[^,)]*%\s*[^,)]*\)/,
    ],
  },
  {
    id: 'py-command-injection',
    name: 'Command Injection',
    description: 'Detects command injection via os.system, subprocess without shell=False',
    severity: 'CRITICAL',
    cwe: 'CWE-78',
    languages: ['python'],
    patterns: [
      /os\.system\s*\(/,
      /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/,
      /subprocess\.(call|run|Popen)\s*\([^)]*\+/,
    ],
  },
  {
    id: 'py-path-traversal',
    name: 'Path Traversal in File Operations',
    description: 'Detects path traversal in file operations (os.path.join misuse)',
    severity: 'HIGH',
    cwe: 'CWE-22',
    languages: ['python'],
    patterns: [
      /open\s*\([^,)]*\+[^,)]*['"]\.\.[\/\\]/,
      /os\.path\.join\s*\([^,)]*\+[^,)]*['"]\.\.[\/\\]/,
    ],
  },
  {
    id: 'py-yaml-deserialization',
    name: 'YAML Deserialization Issues',
    description: 'Detects YAML deserialization issues (yaml.load vs yaml.safe_load)',
    severity: 'HIGH',
    cwe: 'CWE-502',
    languages: ['python'],
    patterns: [
      /yaml\.load\s*\(\s*[^,)]*\s*\)/,
      /yaml\.load\s*\(\s*[^,)]*,\s*Loader\s*=\s*yaml\.Loader\s*\)/,
    ],
  },
];

export const JAVA_RULES: SecurityRule[] = [
  {
    id: 'java-deserialization',
    name: 'Java Deserialization Vulnerability',
    description: 'Detects deserialization vulnerabilities (ObjectInputStream)',
    severity: 'CRITICAL',
    cwe: 'CWE-502',
    languages: ['java'],
    patterns: [
      /ObjectInputStream\s*\([^)]*\)\.readObject\s*\(\s*\)/,
      /new\s+ObjectInputStream\s*\(/,
    ],
  },
  {
    id: 'java-xxe',
    name: 'XXE in XML Parsers',
    description: 'Detects XXE in XML parsers (missing secure processing)',
    severity: 'HIGH',
    cwe: 'CWE-611',
    languages: ['java'],
    patterns: [
      /DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature)/,
      /SAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature)/,
    ],
  },
  {
    id: 'java-jndi-injection',
    name: 'JNDI Injection Vulnerabilities',
    description: 'Detects JNDI injection vulnerabilities',
    severity: 'CRITICAL',
    cwe: 'CWE-74',
    languages: ['java'],
    patterns: [
      /InitialContext\s*\(\s*\)\.lookup\s*\([^)]*\+/,
      /context\.lookup\s*\([^)]*\+/,
    ],
  },
];

export const GO_RULES: SecurityRule[] = [
  {
    id: 'go-command-injection',
    name: 'Command Injection in exec.Command',
    description: 'Detects command injection in exec.Command with untrusted input',
    severity: 'CRITICAL',
    cwe: 'CWE-78',
    languages: ['go'],
    patterns: [
      /exec\.Command\s*\([^,)]*\+[^,)]*\)/,
      /exec\.CommandContext\s*\([^,)]*,[^,)]*\+[^,)]*\)/,
    ],
  },
  {
    id: 'go-path-traversal',
    name: 'Path Traversal in filepath operations',
    description: 'Detects path traversal in filepath operations',
    severity: 'HIGH',
    cwe: 'CWE-22',
    languages: ['go'],
    patterns: [
      /filepath\.Join\s*\([^,)]*\+[^,)]*['"]\.\.[\/\\]/,
      /os\.Open\s*\([^,)]*\+[^,)]*['"]\.\.[\/\\]/,
    ],
  },
];

/**
 * Infinite Loop Detection Rule
 */
export const INFINITE_LOOP_RULE: SecurityRule = {
  id: 'infinite-loop-detection',
  name: 'Infinite Loop Detection',
  description: 'Detects infinite loops by identifying loop constructs where exit condition depends on variables not modified in loop body',
  severity: 'MEDIUM',
  cwe: 'CWE-835',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  patterns: [
    /while\s*\(\s*true\s*\)/,
    /for\s*\(\s*;\s*;\s*\)/,
    /while\s*\(\s*1\s*\)/,
  ],
  customLogic: (code: string, context: any) => {
    // Advanced logic to detect infinite loops
    // This would analyze the loop body to see if exit conditions are modified
    return false; // Placeholder
  },
};

/**
 * Malicious Code Detection Rules
 */
export const MALICIOUS_CODE_RULES: SecurityRule[] = [
  {
    id: 'data-exfiltration',
    name: 'Data Exfiltration Patterns',
    description: 'Detects unauthorized network requests to external domains',
    severity: 'CRITICAL',
    cwe: 'CWE-200',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      /fetch\s*\(\s*['"][^'"]*(?:pastebin|hastebin|requestbin)[^'"]*['"]/,
      /XMLHttpRequest\s*\(\s*\).*open\s*\(\s*['"]POST['"][^)]*(?:pastebin|hastebin)/,
      /requests\.post\s*\(\s*['"][^'"]*(?:pastebin|hastebin)[^'"]*['"]/,
    ],
  },
  {
    id: 'backdoor-detection',
    name: 'Backdoor Detection',
    description: 'Detects hardcoded credentials or hidden administrative endpoints',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    languages: ['javascript', 'typescript', 'python', 'java'],
    patterns: [
      /password\s*=\s*['"]admin123['"]/,
      /if\s*\(\s*password\s*===?\s*['"]backdoor['"]/,
      /\/admin\/secret/,
      /\/debug\/exec/,
    ],
  },
  {
    id: 'obfuscated-code',
    name: 'Obfuscated Code Detection',
    description: 'Detects obfuscated code using Unicode tricks or encodings',
    severity: 'HIGH',
    cwe: 'CWE-506',
    languages: ['javascript', 'typescript'],
    patterns: [
      /\\u[0-9a-fA-F]{4}/,
      /String\.fromCharCode\s*\(/,
      /atob\s*\(/,
      /btoa\s*\(/,
    ],
  },
];

/**
 * Get all security rules
 */
export function getAllSecurityRules(): SecurityRule[] {
  return [
    ...JAVASCRIPT_TYPESCRIPT_RULES,
    ...PYTHON_RULES,
    ...JAVA_RULES,
    ...GO_RULES,
    INFINITE_LOOP_RULE,
    ...MALICIOUS_CODE_RULES,
  ];
}

/**
 * Get rules by language
 */
export function getRulesByLanguage(language: string): SecurityRule[] {
  return getAllSecurityRules().filter(rule => 
    rule.languages.includes(language.toLowerCase())
  );
}

/**
 * Get rules by severity
 */
export function getRulesBySeverity(severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'): SecurityRule[] {
  return getAllSecurityRules().filter(rule => rule.severity === severity);
}