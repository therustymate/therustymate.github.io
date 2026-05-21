---
# the default layout is 'page'
icon: fas fa-diagram-project
order: 4
---

<section class="projects-view">
  <style>
    .projects-view {
      --bg: #0d1117;
      --card: #161b22;
      --card-border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #f97316;
      --accent-soft: rgba(249, 115, 22, 0.14);
      --blue: #58a6ff;
      --green: #3fb950;
      --red: #f85149;

      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background: linear-gradient(135deg, #0d1117 0%, #111827 100%);
      border: 1px solid var(--card-border);
      border-radius: 22px;
      padding: 28px;
      margin: 24px 0;
    }

    .projects-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 24px;
    }

    .projects-title h2 {
      font-size: 1.7rem;
      line-height: 1.2;
      margin: 0 0 8px;
      letter-spacing: -0.03em;
    }

    .projects-title p {
      color: var(--muted);
      margin: 0;
      max-width: 720px;
      line-height: 1.6;
    }

    .projects-badge {
      flex: 0 0 auto;
      border: 1px solid rgba(249, 115, 22, 0.35);
      background: var(--accent-soft);
      color: #ffb86b;
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 0.85rem;
      font-weight: 700;
      white-space: nowrap;
    }

    .projects-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
    }

    .project-card {
      display: flex;
      flex-direction: column;
      min-height: 245px;
      padding: 20px;
      background: rgba(22, 27, 34, 0.92);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      text-decoration: none;
      color: inherit;
      transition: transform 180ms ease, border-color 180ms ease, background 180ms ease;
    }

    .project-card:hover {
      transform: translateY(-4px);
      border-color: rgba(249, 115, 22, 0.6);
      background: rgba(22, 27, 34, 1);
    }

    .project-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 14px;
    }

    .project-icon {
      width: 42px;
      height: 42px;
      display: grid;
      place-items: center;
      border-radius: 14px;
      background: var(--accent-soft);
      color: var(--accent);
      font-size: 1.35rem;
    }

    .project-status {
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--green);
      background: rgba(63, 185, 80, 0.12);
      border: 1px solid rgba(63, 185, 80, 0.28);
      padding: 5px 9px;
      border-radius: 999px;
    }

    .project-status.research {
      color: var(--blue);
      background: rgba(88, 166, 255, 0.12);
      border-color: rgba(88, 166, 255, 0.28);
    }

    .project-status.private {
      color: var(--red);
      background: rgba(248, 81, 73, 0.12);
      border-color: rgba(248, 81, 73, 0.28);
    }

    .project-card h3 {
      font-size: 1.08rem;
      margin: 0 0 10px;
      letter-spacing: -0.02em;
    }

    .project-card p {
      color: var(--muted);
      line-height: 1.55;
      margin: 0 0 16px;
      font-size: 0.94rem;
    }

    .project-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      margin-top: auto;
      padding-top: 12px;
    }

    .project-tags span {
      color: #c9d1d9;
      background: #21262d;
      border: 1px solid #30363d;
      border-radius: 999px;
      padding: 5px 8px;
      font-size: 0.75rem;
      font-weight: 650;
    }

    @media (max-width: 980px) {
      .projects-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 640px) {
      .projects-view {
        padding: 20px;
      }

      .projects-header {
        flex-direction: column;
      }

      .projects-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>

  <div class="projects-header">
    <div class="projects-title">
      <h2>Featured Projects</h2>
      <p>
        A curated collection of my cybersecurity research, reverse engineering work,
        malware analysis reports, vulnerability assessments, and low-level security projects.
      </p>
    </div>
    <div class="projects-badge">therustymate</div>
  </div>

  <div class="projects-grid">
    <a class="project-card" href="/posts/BRKDEC/">
      <div class="project-top">
        <div class="project-icon">⛓️</div>
        <div class="project-status research">Research</div>
      </div>
      <h3>BRKDEC</h3>
      <p>
        Lightweight anti-decompiler research exploring return-address manipulation,
        function-boundary disruption, and CFG reconstruction limitations.
      </p>
      <div class="project-tags">
        <span>Reverse Engineering</span>
        <span>Anti-Decompiler</span>
        <span>x64</span>
      </div>
    </a>

    <a class="project-card" href="/posts/XStringer/">
      <div class="project-top">
        <div class="project-icon">🔐</div>
        <div class="project-status research">Research</div>
      </div>
      <h3>XStringer</h3>
      <p>
        Automated semi-polymorphic string obfuscator for testing decompiler string recovery
        and AI-assisted static reverse engineering capability.
      </p>
      <div class="project-tags">
        <span>Obfuscation</span>
        <span>C/C++</span>
        <span>Binary Security</span>
      </div>
    </a>

    <a class="project-card" href="/posts/MAL-250608-01-01/">
      <div class="project-top">
        <div class="project-icon">🧬</div>
        <div class="project-status">Public</div>
      </div>
      <h3>BPFDoor Analysis</h3>
      <p>
        White-box malware analysis of BPFDoor, including magic packet structure,
        command flow, persistence characteristics, and Linux backdoor behavior.
      </p>
      <div class="project-tags">
        <span>Malware Analysis</span>
        <span>Linux</span>
        <span>RAT</span>
      </div>
    </a>

    <a class="project-card" href="/posts/MAL-250610-01-01/">
      <div class="project-top">
        <div class="project-icon">🪟</div>
        <div class="project-status">Public</div>
      </div>
      <h3>QuasarRAT Analysis</h3>
      <p>
        Black-box malware analysis of QuasarRAT, covering .NET decompilation,
        command structure, API usage, and credential theft modules.
      </p>
      <div class="project-tags">
        <span>Windows</span>
        <span>.NET</span>
        <span>RAT</span>
      </div>
    </a>

    <a class="project-card" href="/posts/tutorly-pentest/">
      <div class="project-top">
        <div class="project-icon">🌐</div>
        <div class="project-status private">Limited</div>
      </div>
      <h3>Tutorly Pentest</h3>
      <p>
        Internal web application penetration test involving access-control review,
        parameter tampering, Supabase/RLS security, and privilege escalation findings.
      </p>
      <div class="project-tags">
        <span>Web Security</span>
        <span>Pentest</span>
        <span>Access Control</span>
      </div>
    </a>

    <a class="project-card" href="/posts/PicoCTF-ropfu/">
      <div class="project-top">
        <div class="project-icon">🧨</div>
        <div class="project-status">Writeup</div>
      </div>
      <h3>PicoCTF ropfu</h3>
      <p>
        Exploit-development writeup covering buffer overflow analysis, ROP gadget selection,
        JMP ESP/JMP EAX control flow, and shell spawning.
      </p>
      <div class="project-tags">
        <span>Exploit Dev</span>
        <span>ROP</span>
        <span>CTF</span>
      </div>
    </a>
  </div>
</section>