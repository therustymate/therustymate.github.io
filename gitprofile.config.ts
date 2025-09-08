// gitprofile.config.ts

const CONFIG = {
  github: {
    username: 'therustymate', // Your GitHub org/user name. (This is the only required config)
  },
  /**
   * If you are deploying to https://<USERNAME>.github.io/, for example your repository is at https://github.com/arifszn/arifszn.github.io, set base to '/'.
   * If you are deploying to https://<USERNAME>.github.io/<REPO_NAME>/,
   * for example your repository is at https://github.com/arifszn/portfolio, then set base to '/portfolio/'.
   */
  base: '/gitprofile/',
  projects: {
    github: {
      display: true, // Display GitHub projects?
      header: 'Github Projects',
      mode: 'automatic', // Mode can be: 'automatic' or 'manual'
      automatic: {
        sortBy: 'stars', // Sort projects by 'stars' or 'updated'
        limit: 6, // How many projects to display.
        exclude: {
          forks: true, // Forked projects will not be displayed if set to true.
          projects: ["therustymate/blog", "therustymate/unofficial-projects", "therustymate/therustymate.github.io"], // These projects will not be displayed. example: ['arifszn/my-project1', 'arifszn/my-project2']
        },
      },
      manual: {
        // Properties for manually specifying projects
        projects: [], // List of repository names to display. example: ['arifszn/my-project1', 'arifszn/my-project2']
      },
    },
    external: {
      header: 'My Projects',
      // To hide the `External Projects` section, keep it empty.
      projects: [
      ],
    },
  },
  seo: { title: 'The Rusty - Profolio', description: 'The Rusty Porfolio Webpage', imageURL: '' },
  social: {
    linkedin: '',
    x: 'therustymate',
    mastodon: '',
    researchGate: '',
    facebook: '',
    instagram: 'therustymate',
    reddit: '',
    threads: '',
    youtube: 'therustymate', // example: 'pewdiepie'
    udemy: '',
    dribbble: '',
    behance: '',
    medium: '',
    dev: 'therustymate',
    stackoverflow: '', // example: '1/jeff-atwood'
    discord: 'therustymate',
    telegram: '',
    website: 'https://therustymate.github.io/blog/',
    phone: '',
    email: 'therustymate@gmail.com',
  },
  resume: {
    fileUrl:
      '', // Empty fileUrl will hide the `Download Resume` button.
  },
  skills: [
    'Kali Linux',

    'VirtualBox',
    'WSL',

    'Ghidra',
    'Binary Ninja',
    'dnSpy',
    'radare2',
    'GDB',

    'Nmap',
    'Metasploit',
    'Netcat',

    'Burp Suite',
    'Gobuster',

    'Wireshark',
    'bettercap',
    'BeEF',

    'Maltego',

    'C#',
    'Python',
    'SQL'
  ],
  experiences: [
    // 2025 August
    {
      company: 'Western Springs College - Student Team Project',
      position: 'Web Application Penetration Tester',
      from: 'August 22, 2025',
      to: 'August 25, 2025',
      companyLink: 'https://docs.google.com/document/d/1D_JfF-JITgqpo786iym6C6imJhe-UGmozzaP9Z8_QHY/edit?usp=sharing',
    },

    // 2025 March - April
    {
      company: 'Western Springs College - Student Team Project',
      position: 'Web Application Penetration Tester',
      from: 'March 31, 2025',
      to: 'April 28, 2025',
      companyLink: 'https://docs.google.com/document/d/1oDtIsZyY3fHIYWuwC2w3e1Sev353pC196TNpXBXQf38/edit?usp=sharing',
    }
  ],
  certifications: [
  ],
  educations: [
  ],
  publications: [
    {
      title: 'WSCW Tuckshop Web Application Penetration Testing',
      conferenceName: 'WSCW',
      journalName: 'Private Report',
      authors: 'The Rusty',
      link: 'https://docs.google.com/document/d/1D_JfF-JITgqpo786iym6C6imJhe-UGmozzaP9Z8_QHY/edit?usp=sharing',
      description:
        'This is the result of the penetration test and the report document for the online store that could potentially used in the tuckshop inside WSCW School.',
    },
    {
      title: 'WSCW Late Sign In Penetration Testing',
      conferenceName: 'WSCW',
      journalName: 'Private Report',
      authors: 'The Rusty',
      link: 'https://docs.google.com/document/d/1oDtIsZyY3fHIYWuwC2w3e1Sev353pC196TNpXBXQf38/edit?usp=sharing',
      description:
        'This is the penetration test result and the report document for the self-reporting website that could potentially used by WSCW students when they are late.',
    },
  ],
  // Display articles from your medium or dev account. (Optional)
  blog: {
    source: 'dev', // medium | dev
    username: 'therustymate', // to hide blog section, keep it empty
    limit: 10, // How many articles to display. Max is 10.
  },
  googleAnalytics: {
    id: 'G-YSLDYLXHP2', // GA3 tracking id/GA4 tag id UA-XXXXXXXXX-X | G-XXXXXXXXXX
  },
  // Track visitor interaction and behavior. https://www.hotjar.com
  hotjar: { id: '', snippetVersion: 6 },
  themeConfig: {
    defaultTheme: 'dark',

    // Hides the switch in the navbar
    // Useful if you want to support a single color mode
    disableSwitch: true,

    // Should use the prefers-color-scheme media-query,
    // using user system preferences, instead of the hardcoded defaultTheme
    respectPrefersColorScheme: false,

    // Display the ring in Profile picture
    displayAvatarRing: true,

    // Available themes. To remove any theme, exclude from here.
    themes: [
      'light',
      'dark',
      'cupcake',
      'bumblebee',
      'emerald',
      'corporate',
      'synthwave',
      'retro',
      'cyberpunk',
      'valentine',
      'halloween',
      'garden',
      'forest',
      'aqua',
      'lofi',
      'pastel',
      'fantasy',
      'wireframe',
      'black',
      'luxury',
      'dracula',
      'cmyk',
      'autumn',
      'business',
      'acid',
      'lemonade',
      'night',
      'coffee',
      'winter',
      'dim',
      'nord',
      'sunset',
      'caramellatte',
      'abyss',
      'silk',
      'procyon',
    ],
  },

  // Optional Footer. Supports plain text or HTML.
  footer: `Made with <a 
      class="text-primary" href="https://github.com/arifszn/gitprofile"
      target="_blank"
      rel="noreferrer"
    >GitProfile</a>`,

  enablePWA: true,
};

export default CONFIG;
