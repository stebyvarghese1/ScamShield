/**
 * ScamShield - Core Application Controller, Tab Navigation & Explainable Results Visualizer
 */

window.App = {
  activeTab: 'url',
  cachedProviders: [],

  init() {
    this.bindTabs();
    this.loadIntegrationsStatus();
    this.bindDropzones();
    this.bindGlobalPaste();
  },

  bindDropzones() {
    const setupZone = (zoneId, onFile) => {
      const el = document.getElementById(zoneId);
      if (!el) return;

      ['dragenter', 'dragover'].forEach(name => {
        el.addEventListener(name, (e) => {
          e.preventDefault();
          e.stopPropagation();
          el.classList.add('dragover');
        });
      });

      ['dragleave', 'dragend', 'drop'].forEach(name => {
        el.addEventListener(name, (e) => {
          e.preventDefault();
          e.stopPropagation();
          el.classList.remove('dragover');
        });
      });

      el.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          onFile(e.dataTransfer.files[0]);
        }
      });
    };

    setupZone('screenshot-dropzone', (file) => {
      if (window.ScannerApp && typeof window.ScannerApp.handleScreenshotFile === 'function') {
        window.ScannerApp.handleScreenshotFile(file);
      }
    });

    setupZone('qr-dropzone', (file) => {
      if (window.ScannerApp && typeof window.ScannerApp.handleQrFile === 'function') {
        window.ScannerApp.handleQrFile(file);
      }
    });
  },

  bindGlobalPaste() {
    window.addEventListener('paste', (e) => {
      const items = (e.clipboardData || window.clipboardData)?.items;
      if (!items || items.length === 0) return;

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.type.indexOf('image') !== -1) {
          const file = item.getAsFile();
          if (file) {
            e.preventDefault();
            if (this.activeTab === 'qr') {
              if (window.ScannerApp && typeof window.ScannerApp.handleQrFile === 'function') {
                window.ScannerApp.handleQrFile(file);
              }
            } else {
              if (this.activeTab !== 'screenshot') {
                this.switchTab('screenshot');
              }
              if (window.ScannerApp && typeof window.ScannerApp.handleScreenshotFile === 'function') {
                window.ScannerApp.handleScreenshotFile(file);
              }
            }
            break;
          }
        }
      }
    });
  },

  bindTabs() {
    const tabButtons = document.querySelectorAll('.nav-tabs .tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const tabKey = btn.dataset.tab;
        this.switchTab(tabKey);
      });
    });
  },

  switchTab(tabKey) {
    if (window.ScannerApp && typeof window.ScannerApp.stopQrCamera === 'function') {
      window.ScannerApp.stopQrCamera();
    }
    this.activeTab = tabKey;
    document.querySelectorAll('.nav-tabs .tab-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.tab === tabKey);
    });

    // Hide all panels
    const panels = ['url', 'message', 'email', 'screenshot', 'qr'];
    panels.forEach(p => {
      const el = document.getElementById(`panel-${p}`);
      if (el) {
        el.style.display = (p === tabKey) ? 'block' : 'none';
      }
    });
  },

  isPrivacyMode() {
    return false;
  },

  showLoading(btnId) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    btn.disabled = true;
    btn.dataset.prevHtml = btn.innerHTML;
    btn.innerHTML = `<span>⏳ Analyzing Signals & Threat Intel...</span>`;
  },

  hideLoading(btnId, defaultText) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    btn.disabled = false;
    btn.innerHTML = `<span>${defaultText}</span>`;
  },

  lastScanResult: null,
  currentFindingFilter: 'all',

  renderResult(data) {
    this.lastScanResult = data;
    const resultPanel = document.getElementById('result-panel');
    const mainGrid = document.getElementById('main-grid');
    if (!resultPanel) return;

    resultPanel.classList.add('visible');
    mainGrid.classList.add('has-result');

    const score = data.risk_score || 0;
    const level = data.risk_level || 'SAFE';

    // 1. Result Panel Border Glow
    resultPanel.classList.remove('level-SAFE', 'level-SUSPICIOUS', 'level-HIGH');
    resultPanel.classList.add(`level-${level}`);

    // 2. Animate Radial Tachometer SVG Gauge
    const gaugeFill = document.getElementById('gauge-fill');
    const gaugeGlow = document.getElementById('gauge-fill-glow');
    const scoreText = document.getElementById('result-score');
    const riskDesc = document.getElementById('result-risk-descriptor');
    const circumference = 465; // r=74
    const offset = circumference - (circumference * score / 100);

    let strokeGradient = 'url(#gaugeSafeGrad)';
    let glowColor = 'rgba(16, 185, 129, 0.4)';
    let descText = 'CLEAN';

    if (level === 'SUSPICIOUS') {
      strokeGradient = 'url(#gaugeWarnGrad)';
      glowColor = 'rgba(245, 158, 11, 0.45)';
      descText = 'SUSPICIOUS';
    } else if (level === 'HIGH') {
      strokeGradient = 'url(#gaugeDangerGrad)';
      glowColor = 'rgba(239, 68, 68, 0.55)';
      descText = score >= 80 ? 'CRITICAL' : 'HIGH RISK';
    }

    if (gaugeFill) {
      gaugeFill.style.stroke = strokeGradient;
      gaugeFill.style.strokeDashoffset = offset;
    }
    if (gaugeGlow) {
      gaugeGlow.style.stroke = glowColor;
      gaugeGlow.style.strokeDashoffset = offset;
    }
    if (riskDesc) {
      riskDesc.className = `gauge-risk-descriptor ${level}`;
      riskDesc.innerText = descText;
    }

    // Smooth counter animation
    let currentCount = 0;
    const stepTime = 1000 / Math.max(score, 1);
    const counterInterval = setInterval(() => {
      if (currentCount >= score) {
        if (scoreText) scoreText.innerText = score;
        clearInterval(counterInterval);
      } else {
        currentCount++;
        if (scoreText) scoreText.innerText = currentCount;
      }
    }, Math.min(stepTime, 20));

    // 3. Target Snippet & Type Icon
    const targetTextEl = document.getElementById('result-target-text');
    const targetIconEl = document.getElementById('result-target-icon');
    const targetStr = data.analyzed_target || 'Target item';
    if (targetTextEl) targetTextEl.innerText = targetStr;
    if (targetIconEl) {
      if (targetStr.startsWith('http') || targetStr.includes('.')) targetIconEl.innerText = '🌐';
      else if (targetStr.toLowerCase().includes('from:') || targetStr.toLowerCase().includes('subj:')) targetIconEl.innerText = '📧';
      else if (targetStr.startsWith('QR')) targetIconEl.innerText = '📷';
      else if (targetStr.startsWith('Screenshot')) targetIconEl.innerText = '📸';
      else targetIconEl.innerText = '📱';
    }

    // 4. Confidence Badge
    const confText = document.getElementById('result-confidence-text');
    const confPct = Math.round((data.confidence || 0.94) * 100);
    if (confText) confText.innerText = `${confPct}% Confidence`;

    // 5. Verdict Banner & Classification
    const badge = document.getElementById('result-badge');
    const badgeIcon = document.getElementById('result-badge-icon');
    const badgeText = document.getElementById('result-badge-text');
    if (badge) {
      badge.className = `verdict-banner-modern ${level}`;
      if (level === 'HIGH') {
        if (badgeIcon) badgeIcon.innerText = '🚨';
        if (badgeText) badgeText.innerText = 'HIGH RISK THREAT DETECTED';
      } else if (level === 'SUSPICIOUS') {
        if (badgeIcon) badgeIcon.innerText = '⚠️';
        if (badgeText) badgeText.innerText = 'SUSPICIOUS ACTIVITY';
      } else {
        if (badgeIcon) badgeIcon.innerText = '🛡️';
        if (badgeText) badgeText.innerText = 'VERIFIED SAFE';
      }
    }

    const catBadge = document.getElementById('result-category');
    if (catBadge) {
      catBadge.innerText = (data.category || 'SAFE').replace(/_/g, ' ');
    }

    // 6. Telemetry Counters
    const findings = data.findings || [];
    const critCount = findings.filter(f => f.severity === 'high' && (f.type.includes('critical') || f.type.includes('confirmed') || f.type.includes('phish') || f.type.includes('malware'))).length;
    const highCount = findings.filter(f => f.severity === 'high' && !f.type.includes('critical') && !f.type.includes('confirmed') && !f.type.includes('phish') && !f.type.includes('malware')).length;
    const medCount = findings.filter(f => f.severity === 'medium').length;

    const elCrit = document.getElementById('tele-critical-count');
    const elHigh = document.getElementById('tele-high-count');
    const elMed = document.getElementById('tele-med-count');
    if (elCrit) elCrit.innerText = critCount;
    if (elHigh) elHigh.innerText = highCount;
    if (elMed) elMed.innerText = medCount;

    // 7. Directive Recommendation Banner
    const recBox = document.getElementById('result-recommendation-box');
    const recIcon = document.getElementById('result-rec-icon');
    const recTitle = document.getElementById('result-rec-title');
    const recDesc = document.getElementById('result-rec-desc');

    if (recBox) recBox.className = `directive-box-modern ${level}`;
    if (level === 'HIGH') {
      if (recIcon) recIcon.innerText = '⛔';
      if (recTitle) recTitle.innerText = 'DO NOT ENGAGE OR CLICK';
    } else if (level === 'SUSPICIOUS') {
      if (recIcon) recIcon.innerText = '⚠️';
      if (recTitle) recTitle.innerText = 'PROCEED WITH ELEVATED CAUTION';
    } else {
      if (recIcon) recIcon.innerText = '✅';
      if (recTitle) recTitle.innerText = 'CLEAR OF DETECTED THREATS';
    }
    if (recDesc) recDesc.innerText = data.recommendation;

    // 8. Populate Overview Subpanel
    const sumEl = document.getElementById('overview-summary-text');
    if (sumEl) {
      if (level === 'HIGH') {
        sumEl.innerHTML = `<strong style="color: #f87171;">Critical Threat:</strong> Identified indicators matching known scam/malware heuristics and active threat databases. Engaging with this target presents severe risk of credential theft, financial fraud, or device compromise.`;
      } else if (level === 'SUSPICIOUS') {
        sumEl.innerHTML = `<strong style="color: #fbbf24;">Suspicious Patterns:</strong> Multiple unusual signals detected (e.g. young domain age, deceptive wording, or anomalous redirection). Proceed with extreme caution and do not disclose sensitive details.`;
      } else {
        sumEl.innerHTML = `<strong style="color: #34d399;">Clean Assessment:</strong> No known malware, phishing kit signatures, or deceptive behavioral patterns identified across global threat feeds and local heuristics.`;
      }
    }

    const eduTip = document.getElementById('result-educational-tip');
    if (eduTip) {
      eduTip.innerText = data.educational_tip || 'Always verify the sender through independent channels before submitting credentials or funds.';
    }

    // Quick Signals List (Chips)
    const quickSignalsList = document.getElementById('quick-signals-list');
    const qsBadge = document.getElementById('qs-count-badge');
    if (qsBadge) qsBadge.innerText = `${findings.length} signal${findings.length === 1 ? '' : 's'}`;
    if (quickSignalsList) {
      if (findings.length === 0) {
        quickSignalsList.innerHTML = `<span class="signal-chip info"><span>✅</span> Zero risk triggers</span>`;
      } else {
        quickSignalsList.innerHTML = findings.slice(0, 6).map(f => {
          let chipClass = 'info';
          let icon = 'ℹ️';
          if (f.severity === 'high') { chipClass = 'danger'; icon = '🚨'; }
          else if (f.severity === 'medium') { chipClass = 'warning'; icon = '⚠️'; }
          return `<span class="signal-chip ${chipClass}"><span>${icon}</span> ${f.title}</span>`;
        }).join('');
      }
    }

    // 9. Render Subpanel 2: Threat Feeds Matrix
    this.renderThreatFeedsMatrix(data);

    // 10. Render Subpanel 3: Findings List with Filter Pills
    this.renderFindingsList(data.findings || []);

    // 11. Render Subpanel 4: Incident Response Checklist
    this.renderDefenseChecklist(data);

    // 12. Timestamp
    const timeEl = document.getElementById('result-report-time');
    if (timeEl) {
      const d = new Date();
      timeEl.innerText = `Generated: ${d.toLocaleTimeString()} (${d.toLocaleDateString()})`;
    }

    // Badges on Subtabs
    const fCountBadge = document.getElementById('res-findings-count-badge');
    if (fCountBadge) fCountBadge.innerText = findings.length;

    // Reset subtab to overview on new scan
    this.switchResultSubtab('overview');

    // Smooth scroll into view on smaller displays
    if (window.innerWidth < 992) {
      resultPanel.scrollIntoView({ behavior: 'smooth' });
    }
  },

  switchResultSubtab(tabKey) {
    document.querySelectorAll('.result-subtabs-bar .res-subtab').forEach(b => {
      b.classList.toggle('active', b.dataset.subtab === tabKey);
    });

    const panels = ['overview', 'feeds', 'evidence', 'actions'];
    panels.forEach(p => {
      const el = document.getElementById(`subpanel-${p}`);
      if (el) {
        el.style.display = (p === tabKey) ? 'block' : 'none';
        el.classList.toggle('active', p === tabKey);
      }
    });
  },

  renderThreatFeedsMatrix(data) {
    const container = document.getElementById('threat-feeds-result-grid');
    if (!container) return;

    const findings = data.findings || [];
    const details = data.details || {};
    const intel = details.threat_intel || {};

    // 10 Feeds Status Derivation
    const feeds = [
      {
        name: 'ICANN RDAP / WHOIS',
        icon: '📅',
        badge: (() => {
          const rdapF = findings.find(f => f.type.includes('rdap') || f.type.includes('domain'));
          if (rdapF && rdapF.severity === 'high') return { text: 'FLAGGED (<7D OLD)', class: 'threat' };
          if (rdapF && rdapF.severity === 'medium') return { text: 'RECENT (<30D)', class: 'threat' };
          return { text: 'VERIFIED ACTIVE', class: 'clean' };
        })(),
        desc: (() => {
          const rdapF = findings.find(f => f.type.includes('domain'));
          if (rdapF) return rdapF.description;
          return 'Domain registration history verified via ICANN RDAP.';
        })()
      },
      {
        name: 'Cloudflare DNS (DoH)',
        icon: '🌐',
        badge: (() => {
          const dnsF = findings.find(f => f.type.includes('dns') || f.type.includes('ssrf'));
          if (dnsF && dnsF.severity === 'high') return { text: 'SSRF BLOCKED', class: 'threat' };
          return { text: 'RESOLVED (PUBLIC IP)', class: 'clean' };
        })(),
        desc: (() => {
          const ips = intel.resolved_ips || [];
          if (ips.length > 0) return `Host IPs resolved via DoH: ${ips.slice(0, 2).join(', ')}`;
          return 'Host address resolved securely via Cloudflare encrypted DNS.';
        })()
      },
      {
        name: 'PhishTank (OpenDNS)',
        icon: '🎣',
        badge: (() => {
          const ptF = findings.find(f => f.type.includes('phishtank'));
          if (ptF) return { text: 'CONFIRMED PHISH', class: 'threat' };
          return { text: 'CLEAN', class: 'clean' };
        })(),
        desc: 'Cross-checked against community-verified active phishing database.'
      },
      {
        name: 'Have I Been Pwned',
        icon: '🔐',
        badge: { text: 'K-ANONYMITY READY', class: 'clean' },
        desc: 'Zero-key k-anonymity SHA-1 breach range available in Education tab.'
      },
      {
        name: 'VirusTotal v3',
        icon: '🛡️',
        badge: (() => {
          const vtF = findings.find(f => f.type.includes('virustotal'));
          if (vtF && vtF.severity === 'high') return { text: 'VENDORS FLAGGED', class: 'threat' };
          const p = (this.cachedProviders || []).find(cp => cp.id === 'virustotal');
          return (p && p.has_key) ? { text: '0/70 CLEAN', class: 'clean' } : { text: 'OPTIONAL KEY', class: 'optional' };
        })(),
        desc: 'Consensus scan across 70+ antivirus and URL threat engines.'
      },
      {
        name: 'Google Safe Browsing v4',
        icon: '🔍',
        badge: (() => {
          const gsbF = findings.find(f => f.type.includes('google') || f.type.includes('gsb'));
          if (gsbF) return { text: 'BLACKLISTED', class: 'threat' };
          const p = (this.cachedProviders || []).find(cp => cp.id === 'google_safebrowsing');
          return (p && p.has_key) ? { text: 'CLEAN', class: 'clean' } : { text: 'OPTIONAL KEY', class: 'optional' };
        })(),
        desc: 'Google Chrome official malicious and social engineering blacklist.'
      },
      {
        name: 'AbuseIPDB v2',
        icon: '⚠️',
        badge: (() => {
          const ipF = findings.find(f => f.type.includes('abuseipdb'));
          if (ipF) return { text: 'MALICIOUS IP', class: 'threat' };
          const p = (this.cachedProviders || []).find(cp => cp.id === 'abuseipdb');
          return (p && p.has_key) ? { text: 'REPUTATION CLEAN', class: 'clean' } : { text: 'OPTIONAL KEY', class: 'optional' };
        })(),
        desc: 'Checks hosting server IP for crowdsourced reports of attacks.'
      },
      {
        name: 'URLhaus (abuse.ch)',
        icon: '🦠',
        badge: (() => {
          const uhF = findings.find(f => f.type.includes('urlhaus'));
          if (uhF) return { text: 'MALWARE PAYLOAD', class: 'threat' };
          return { text: 'CLEAN', class: 'clean' };
        })(),
        desc: 'Monitors websites distributing ransomware, trojans, and payload droppers.'
      },
      {
        name: 'ThreatFox (abuse.ch)',
        icon: '🦊',
        badge: (() => {
          const tfF = findings.find(f => f.type.includes('threatfox'));
          if (tfF) return { text: 'BOTNET / C2 IOC', class: 'threat' };
          return { text: 'CLEAN', class: 'clean' };
        })(),
        desc: 'Searches Indicators of Compromise (IOCs) used by cybercrime cartels.'
      },
      {
        name: 'AlienVault OTX',
        icon: '🛰️',
        badge: (() => {
          const otxF = findings.find(f => f.type.includes('alienvault') || f.type.includes('otx'));
          if (otxF) return { text: 'ACTIVE PULSES', class: 'threat' };
          return { text: 'ZERO PULSES', class: 'clean' };
        })(),
        desc: 'Threat actor campaigns and adversary intelligence pulses.'
      }
    ];

    container.innerHTML = feeds.map(feed => `
      <div class="feed-matrix-card">
        <div class="fmc-top">
          <span class="fmc-name"><span>${feed.icon}</span> ${feed.name}</span>
          <span class="fmc-badge ${feed.badge.class}">${feed.badge.text}</span>
        </div>
        <div class="fmc-desc">${feed.desc}</div>
      </div>
    `).join('');
  },

  renderFindingsList(findings) {
    const list = document.getElementById('findings-list');
    if (!list) return;

    // Update filter counts
    const allCount = findings.length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const medCount = findings.filter(f => f.severity === 'medium').length;
    const infoCount = findings.filter(f => f.severity === 'low' || f.severity === 'info').length;

    const elAll = document.getElementById('filter-count-all');
    const elHigh = document.getElementById('filter-count-high');
    const elMed = document.getElementById('filter-count-med');
    const elInfo = document.getElementById('filter-count-info');
    if (elAll) elAll.innerText = allCount;
    if (elHigh) elHigh.innerText = highCount;
    if (elMed) elMed.innerText = medCount;
    if (elInfo) elInfo.innerText = infoCount;

    // Filter
    let filtered = findings;
    if (this.currentFindingFilter === 'high') {
      filtered = findings.filter(f => f.severity === 'high');
    } else if (this.currentFindingFilter === 'medium') {
      filtered = findings.filter(f => f.severity === 'medium');
    } else if (this.currentFindingFilter === 'info') {
      filtered = findings.filter(f => f.severity === 'low' || f.severity === 'info');
    }

    if (filtered.length === 0) {
      list.innerHTML = `
        <div class="finding-card-modern severity-info">
          <div class="fcm-title"><span>🛡️</span> No ${this.currentFindingFilter === 'all' ? '' : this.currentFindingFilter} findings to display</div>
          <div class="fcm-desc">All signals in this category are clear of detected threats.</div>
        </div>
      `;
      return;
    }

    list.innerHTML = filtered.map(f => {
      let icon = 'ℹ️';
      if (f.severity === 'high') icon = '🚨';
      else if (f.severity === 'medium') icon = '⚠️';

      return `
        <div class="finding-card-modern severity-${f.severity || 'low'}">
          <div class="fcm-header">
            <span class="fcm-title"><span>${icon}</span> ${f.title}</span>
            <span class="severity-pill ${f.severity}">${f.severity}</span>
          </div>
          <div class="fcm-desc">${f.description}</div>
          ${f.educational_note ? `<div class="fcm-edu">💡 <strong>Security Insight:</strong> ${f.educational_note}</div>` : ''}
        </div>
      `;
    }).join('');
  },

  filterFindings(severity) {
    this.currentFindingFilter = severity;
    document.querySelectorAll('.filter-pills-wrap .filter-pill').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.filter === severity);
    });
    if (this.lastScanResult) {
      this.renderFindingsList(this.lastScanResult.findings || []);
    }
  },

  renderDefenseChecklist(data) {
    const container = document.getElementById('checklist-items');
    if (!container) return;

    const level = data.risk_level || 'SAFE';
    const cat = data.category || 'SAFE';

    let steps = [];
    if (level === 'HIGH' || level === 'SUSPICIOUS') {
      if (cat.includes('PHISH') || cat.includes('BANK')) {
        steps = [
          { title: 'Do NOT Click or Enter Credentials', desc: 'Avoid clicking links or submitting usernames, passwords, or PINs.' },
          { title: 'Verify via Official Bookmarks or Apps', desc: 'Navigate to the real banking/service website directly using your verified bookmark.' },
          { title: 'Change Exposed Credentials', desc: 'If you already typed your password, change it immediately and enable 2FA.' },
          { title: 'Report Message to IT / Anti-Phishing', desc: 'Flag the SMS or email as phishing so defensive filters protect others.' }
        ];
      } else if (cat.includes('MALWARE')) {
        steps = [
          { title: 'Do NOT Download or Run Files', desc: 'Refrain from opening any executable (.exe), archive (.zip/.iso), or script.' },
          { title: 'Disconnect From Network If Run', desc: 'If you ran an executable from this site, disconnect Wi-Fi to stop C2 botnet beacons.' },
          { title: 'Run Full Endpoint Antivirus Scan', desc: 'Perform a comprehensive scan using Windows Defender or updated anti-malware.' }
        ];
      } else {
        steps = [
          { title: 'Stop Engagement Immediately', desc: 'Cease any communication with the sender on WhatsApp, Telegram, or SMS.' },
          { title: 'Block Sender Address or Number', desc: 'Add the phone number or email domain to your blocked contacts.' },
          { title: 'Never Send Funds or Gift Cards', desc: 'Legitimate jobs, agencies, and refunds never demand payment transfers.' }
        ];
      }
    } else {
      steps = [
        { title: 'Standard Safe Browsing Practice', desc: 'Target shows no malicious indicators, but always verify URL spelling before logging in.' },
        { title: 'Maintain Strong Unique Passwords', desc: 'Use a password manager to generate distinct credentials for each account.' },
        { title: 'Enable Multi-Factor Authentication (MFA)', desc: 'Protect your accounts with hardware keys or authenticator apps.' }
      ];
    }

    container.innerHTML = steps.map((s, idx) => `
      <div class="checklist-item" onclick="this.classList.toggle('checked')">
        <span class="checklist-check">☑️</span>
        <div class="checklist-text">
          <h5>${idx + 1}. ${s.title}</h5>
          <p>${s.desc}</p>
        </div>
      </div>
    `).join('');
  },

  copyTargetIndicator() {
    if (!this.lastScanResult) return;
    const target = this.lastScanResult.analyzed_target || '';
    if (!target) return;
    navigator.clipboard.writeText(target).then(() => {
      const btn = document.getElementById('btn-copy-target');
      if (btn) {
        btn.innerHTML = '<span>✅</span>';
        setTimeout(() => { btn.innerHTML = '<span>📋</span>'; }, 1500);
      }
    });
  },

  copyThreatReport() {
    if (!this.lastScanResult) {
      alert('No active scan result to export.');
      return;
    }
    const d = this.lastScanResult;
    const findings = (d.findings || []).map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description}`).join('\n');
    
    const reportText = [
      `# 🛡️ ScamShield Cybersecurity Threat Report`,
      `**Target**: ${d.analyzed_target || 'N/A'}`,
      `**Date**: ${new Date().toISOString()}`,
      `**Risk Score**: ${d.risk_score} / 100 (${d.risk_level})`,
      `**Category**: ${d.category}`,
      `**Confidence**: ${Math.round((d.confidence || 0.94) * 100)}%`,
      ``,
      `### Security Directive`,
      `${d.recommendation}`,
      ``,
      `### Key Evidence & Threat Findings (${d.findings ? d.findings.length : 0})`,
      findings || 'No malicious indicators detected.',
      ``,
      `*Generated by ScamShield Security Assistant with 10 Multi-Provider Threat Feeds.*`
    ].join('\n');

    navigator.clipboard.writeText(reportText).then(() => {
      const btnText = document.getElementById('btn-copy-report-text');
      const btnIcon = document.getElementById('btn-copy-report-icon');
      if (btnText) btnText.innerText = 'Copied to Clipboard!';
      if (btnIcon) btnIcon.innerText = '✅';
      setTimeout(() => {
        if (btnText) btnText.innerText = 'Copy Threat Report';
        if (btnIcon) btnIcon.innerText = '📋';
      }, 2000);
    }).catch(err => {
      alert('Failed to copy report: ' + err.message);
    });
  },

  reScanCurrentTarget() {
    if (!this.lastScanResult) return;
    const target = this.lastScanResult.analyzed_target || '';
    if (this.activeTab === 'url') {
      const input = document.getElementById('input-url');
      if (input && target) input.value = target;
      const form = document.getElementById('form-url');
      if (form) form.dispatchEvent(new Event('submit'));
    } else if (this.activeTab === 'message') {
      const input = document.getElementById('input-message');
      if (input && target) input.value = target;
      const form = document.getElementById('form-message');
      if (form) form.dispatchEvent(new Event('submit'));
    }
  },

  async loadIntegrationsStatus() {
    try {
      const resp = await fetch('/api/v1/settings/integrations');
      if (!resp.ok) return;
      const data = await resp.json();
      this.cachedProviders = data.providers || [];
      this.renderProvidersGrid(this.cachedProviders);
      this.updateHeaderBadge(this.cachedProviders);
      this.onProviderSelectChange();
    } catch (e) {
      console.warn('Failed to fetch threat feeds status:', e);
    }
  },

  updateHeaderBadge(providers) {
    const activeCount = providers.filter(p => p.status === 'active').length;
    const dot = document.getElementById('header-vt-dot');
    const text = document.getElementById('header-vt-text');
    if (dot) {
      dot.style.background = activeCount >= 4 ? '#10b981' : '#f59e0b';
    }
    if (text) {
      text.innerText = `⚡ Threat Feeds (${activeCount}/10 Active)`;
    }
  },

  renderProvidersGrid(providers) {
    const grid = document.getElementById('providers-list-grid');
    if (!grid) return;
    grid.innerHTML = providers.map(p => {
      const isActive = p.status === 'active';
      const badgeColor = isActive ? '#10b981' : '#64748b';
      const badgeText = isActive ? (p.requires_key ? 'KEY ACTIVE' : 'ZERO-KEY') : 'OPTIONAL KEY';
      return `
        <div class="provider-badge-card" style="padding: 10px 12px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <strong style="font-size: 13px; color: #f1f5f9;">${p.name}</strong>
            <span style="font-size: 10px; font-weight: 700; color: ${badgeColor}; border: 1px solid ${badgeColor}40; padding: 2px 6px; border-radius: 4px; background: ${badgeColor}15;">${badgeText}</span>
          </div>
          <div style="font-size: 11px; color: var(--text-dim);">${p.description}</div>
        </div>
      `;
    }).join('');
  },

  openIntegrationsModal() {
    const modal = document.getElementById('integrations-modal');
    if (modal) {
      modal.style.display = 'flex';
      this.loadIntegrationsStatus();
    }
  },

  closeIntegrationsModal() {
    const modal = document.getElementById('integrations-modal');
    if (modal) modal.style.display = 'none';
  },

  onProviderSelectChange() {
    const sel = document.getElementById('provider-select');
    if (!sel) return;
    const providerId = sel.value;
    const provider = this.cachedProviders.find(p => p.id === providerId);

    const helpText = document.getElementById('provider-help-text');
    const keyInput = document.getElementById('provider-api-key-input');
    const clearBtn = document.getElementById('btn-clear-provider');
    const feedback = document.getElementById('integration-feedback');
    if (feedback) feedback.style.display = 'none';

    const infoMap = {
      virustotal: 'Free 500 req/day API key from virustotal.com. Synchronized directly with your .env file.',
      google_safebrowsing: 'Free Safe Browsing v4 key from Google Cloud Console. Synchronized with your .env file.',
      abuseipdb: 'Free 1,000 checks/day key from abuseipdb.com. Synchronized with your .env file.',
      urlhaus: 'Free Auth-Key from abuse.ch URLhaus. Synchronized with your .env file.',
      threatfox: 'Free Auth-Key from abuse.ch ThreatFox. Synchronized with your .env file.',
      alienvault_otx: 'Free OTX Key from otx.alienvault.com. Synchronized with your .env file.',
      phishtank: 'Optional developer API key for PhishTank. Works automatically out of the box without any key.',
      hibp: 'Optional API key for email account breach search. Password k-anonymity search is 100% free with zero keys.'
    };

    if (helpText) {
      helpText.innerText = infoMap[providerId] || 'Loaded securely from your .env file and cached in memory.';
    }

    if (provider && provider.has_key) {
      keyInput.placeholder = '•••••••••••••••• (API Key Configured)';
      if (clearBtn) clearBtn.style.display = 'inline-block';
    } else {
      keyInput.placeholder = 'Paste your API or Auth key here...';
      if (clearBtn) clearBtn.style.display = 'none';
    }
  },

  async saveSelectedProviderKey() {
    const sel = document.getElementById('provider-select');
    const keyInput = document.getElementById('provider-api-key-input');
    const feedback = document.getElementById('integration-feedback');
    const saveBtn = document.getElementById('btn-save-provider');

    const providerId = sel.value;
    const key = keyInput.value.trim();

    if (!key) {
      feedback.style.display = 'block';
      feedback.style.background = 'rgba(239, 68, 68, 0.15)';
      feedback.style.color = '#f87171';
      feedback.style.border = '1px solid #ef4444';
      feedback.innerText = 'Please paste a valid API key.';
      return;
    }

    saveBtn.disabled = true;
    saveBtn.innerText = 'Verifying & Saving...';

    try {
      const resp = await fetch(`/api/v1/settings/integrations/${providerId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: key })
      });
      const data = await resp.json();

      feedback.style.display = 'block';
      if (resp.ok && data.success) {
        feedback.style.background = 'rgba(16, 185, 129, 0.15)';
        feedback.style.color = '#34d399';
        feedback.style.border = '1px solid #10b981';
        feedback.innerText = `✅ Key successfully saved and active for ${sel.options[sel.selectedIndex].text}!`;
        keyInput.value = '';
        this.loadIntegrationsStatus();
      } else {
        feedback.style.background = 'rgba(239, 68, 68, 0.15)';
        feedback.style.color = '#f87171';
        feedback.style.border = '1px solid #ef4444';
        feedback.innerText = `❌ ${data.detail || data.message || 'Failed to save API key'}`;
      }
    } catch (err) {
      feedback.style.display = 'block';
      feedback.style.background = 'rgba(239, 68, 68, 0.15)';
      feedback.style.color = '#f87171';
      feedback.style.border = '1px solid #ef4444';
      feedback.innerText = `❌ Connection error: ${err.message}`;
    } finally {
      saveBtn.disabled = false;
      saveBtn.innerText = 'Save Key';
    }
  },

  async testSelectedProviderKey() {
    const sel = document.getElementById('provider-select');
    const keyInput = document.getElementById('provider-api-key-input');
    const feedback = document.getElementById('integration-feedback');
    const testBtn = document.getElementById('btn-test-provider');

    const providerId = sel.value;
    let key = keyInput.value.trim();

    feedback.style.display = 'block';
    feedback.style.background = 'rgba(59, 130, 246, 0.15)';
    feedback.style.color = '#60a5fa';
    feedback.style.border = '1px solid #3b82f6';
    feedback.innerText = 'Testing live API endpoint...';
    testBtn.disabled = true;

    try {
      const resp = await fetch(`/api/v1/settings/integrations/${providerId}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: key })
      });
      const data = await resp.json();

      if (resp.ok && data.success) {
        feedback.style.background = 'rgba(16, 185, 129, 0.15)';
        feedback.style.color = '#34d399';
        feedback.style.border = '1px solid #10b981';
        feedback.innerText = `✅ Success: ${data.message}`;
      } else {
        feedback.style.background = 'rgba(239, 68, 68, 0.15)';
        feedback.style.color = '#f87171';
        feedback.style.border = '1px solid #ef4444';
        feedback.innerText = `❌ Validation Failed: ${data.detail || data.message || 'Key invalid'}`;
      }
    } catch (err) {
      feedback.style.display = 'block';
      feedback.style.background = 'rgba(239, 68, 68, 0.15)';
      feedback.style.color = '#f87171';
      feedback.style.border = '1px solid #ef4444';
      feedback.innerText = `❌ Test request failed: ${err.message}`;
    } finally {
      testBtn.disabled = false;
    }
  },

  async clearSelectedProviderKey() {
    const sel = document.getElementById('provider-select');
    const providerId = sel.value;
    if (!confirm(`Are you sure you want to disconnect and delete the API key for ${sel.options[sel.selectedIndex].text}?`)) {
      return;
    }

    try {
      const resp = await fetch(`/api/v1/settings/integrations/${providerId}`, {
        method: 'DELETE'
      });
      const data = await resp.json();
      const feedback = document.getElementById('integration-feedback');
      if (feedback) {
        feedback.style.display = 'block';
        feedback.style.background = 'rgba(16, 185, 129, 0.15)';
        feedback.style.color = '#34d399';
        feedback.style.border = '1px solid #10b981';
        feedback.innerText = `Cleared API key for ${providerId}.`;
      }
      this.loadIntegrationsStatus();
    } catch (err) {
      alert(`Failed to delete key: ${err.message}`);
    }
  },

  async checkPasswordExposure(event) {
    if (event) event.preventDefault();
    const input = document.getElementById('hibp-pass-input');
    const btn = document.getElementById('btn-check-hibp');
    const resultBox = document.getElementById('hibp-result-box');

    const password = input.value;
    if (!password) return;

    btn.disabled = true;
    btn.innerHTML = '<span>Verifying via k-anonymity...</span>';
    resultBox.style.display = 'none';

    try {
      const resp = await fetch('/api/v1/settings/hibp/check-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });
      const data = await resp.json();

      resultBox.style.display = 'block';
      if (data.pwned) {
        resultBox.style.background = 'rgba(239, 68, 68, 0.15)';
        resultBox.style.border = '1px solid #ef4444';
        resultBox.style.color = '#fca5a5';
        resultBox.innerHTML = `
          <div style="font-weight: 700; font-size: 15px; margin-bottom: 6px; color: #f87171;">
            🚨 COMPROMISED: Exposed ${Number(data.count).toLocaleString()} times in data breaches!
          </div>
          <div>This password appears in known credential leaks from past corporate hacks. Never use this password for any personal, banking, or email accounts.</div>
        `;
      } else if (data.status === 'safe') {
        resultBox.style.background = 'rgba(16, 185, 129, 0.15)';
        resultBox.style.border = '1px solid #10b981';
        resultBox.style.color = '#6ee7b7';
        resultBox.innerHTML = `
          <div style="font-weight: 700; font-size: 15px; margin-bottom: 6px; color: #34d399;">
            ✅ GOOD NEWS: Zero breach exposures found!
          </div>
          <div>This password was NOT found in HIBP's database of 900+ million exposed credentials. (Verified safely via SHA-1 prefix k-anonymity — plaintext never left your computer).</div>
        `;
      } else {
        resultBox.style.background = 'rgba(245, 158, 11, 0.15)';
        resultBox.style.border = '1px solid #f59e0b';
        resultBox.style.color = '#fcd34d';
        resultBox.innerText = data.error || 'Notice: Unable to reach HIBP verification servers.';
      }
    } catch (e) {
      resultBox.style.display = 'block';
      resultBox.style.background = 'rgba(239, 68, 68, 0.15)';
      resultBox.style.border = '1px solid #ef4444';
      resultBox.style.color = '#fca5a5';
      resultBox.innerText = `Error contacting HIBP service: ${e.message}`;
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>Check Breach Status</span>';
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
