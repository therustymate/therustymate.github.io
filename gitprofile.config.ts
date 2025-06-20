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
  base: '/',
  projects: {
    github: {
      display: true, // Display GitHub projects?
      header: 'Github Projects',
      mode: 'automatic', // Mode can be: 'automatic' or 'manual'
      automatic: {
        sortBy: 'stars', // Sort projects by 'stars' or 'updated'
        limit: 16, // How many projects to display.
        exclude: {
          forks: true, // Forked projects will not be displayed if set to true.
          projects: [], // These projects will not be displayed. example: ['arifszn/my-project1', 'arifszn/my-project2']
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
        {
          title: 'WatchCat',
          description:
            'The WatchCat project is a powerful local network device identification program.',
          imageUrl:
            './unofficial-projects/WatchCat/logo.png',
          link: './unofficial-projects/WatchCat',
        },
        {
          title: 'Elite',
          description:
            'Elite project is a network MITM (Man-In-The-Middle) attack tool designed for local network penetration testing.',
          imageUrl:
            './unofficial-projects/Elite/logo.png',
          link: './unofficial-projects/Elite',
        },
        {
          title: 'Elite Console',
          description:
            'Elite Console project is an enhanced and high-performance MITM (Man-In-The-Middle) attack tool, designed for advanced capabilities for network penetration testing.',
          imageUrl:
            './unofficial-projects/Elite Console/logo.png',
          link: './unofficial-projects/Elite Console',
        },
        {
          title: 'Elite++',
          description:
            'Elite++ project integrates the Elite project with the Elite Console project, which combines the powerful and clear UI of the Elite Project with the power of the Elite Console project.',
          imageUrl:
            './unofficial-projects/Elite++/logo.png',
          link: './unofficial-projects/Elite++',
        },
      ],
    },
  },
  seo: {
    title: 'The Rusty - Portfolio',
    description: "The Rusty's Portfolio Website (@therustymate)",
    imageURL: 'https://avatars.githubusercontent.com/u/216290241?v=4',
  },
  social: {
    linkedin: '',
    x: '',
    mastodon: '',
    researchGate: '',
    facebook: '',
    instagram: '',
    reddit: '',
    threads: '',
    youtube: 'therustymate', // example: 'pewdiepie'
    udemy: '',
    dribbble: '',
    behance: '',
    medium: '',
    dev: 'therustymate',
    stackoverflow: '', // example: '1/jeff-atwood'
    skype: '',
    telegram: '',
    website: 'https://therustymate.github.io/',
    phone: '',
    email: 'therustymate@gmail.com',
  },
  resume: {
    fileUrl:
      '', // Empty fileUrl will hide the `Download Resume` button.
  },
  skills: [
    'Kali Linux',
    'BlackArch',
    'VirtualBox',
    'WSL',
    'QEMU',
    'Ventoy',
    'Ghidra',
    'Binary Ninja',
    'dnSpy',
    'ILSpy',
    'radare2',
    'Nmap',
    'Metasploit',
    'Burp Suite',
    'ZAP',
    'mitmproxy',
    'XAMPP',
    'TMAC',
    'Maltego',
    'FileZila',
    'Bulk Extractor',
    'Reverse Engineering',
    'Cryptography',
    'Web Hacking',
    'Binary Exploitation',
    'Penetration Testing',
    'Malware Analysis',
    'Red Teaming',
    'Network Hacking',
    'Assembly (x86)',
    'C',
    'C++',
    'C#',
    'Python',
    'PHP',
    'HTML',
    'JavaScript',
    'Oracle (SQL)',
    'Microsoft (SQL)',
    'PostgreSQL',
    'MySQL'
  ],
  experiences: [
    {
      company: 'A Public School',
      position: 'Unofficial Incident Responder',
      from: '2024-10/08',
      to: '2025-03/06',
      companyLink: './unofficial-projects/unofficial_incident_respond',
    },
    {
      company: 'Private Programming Team',
      position: 'Web Application Penetration Tester',
      from: '2025-03/31',
      to: '2025-04/28',
      companyLink: './unofficial-projects/unofficial_school_latesignin',
    }
  ],
  certifications: [
    {
      name: 'Lorem ipsum (test)',
      body: 'Lorem ipsum dolor sit amet',
      year: 'March 2022',
      link: 'https://example.com',
    },
  ],
  educations: [
    // {
    //   institution: 'Institution Name',
    //   degree: 'Degree',
    //   from: '2015',
    //   to: '2019',
    // },
    // {
    //   institution: 'Institution Name',
    //   degree: 'Degree',
    //   from: '2012',
    //   to: '2014',
    // },
  ],
  publications: [
    // {
    //   title: 'Publication Title',
    //   conferenceName: '',
    //   journalName: 'Journal Name',
    //   authors: 'John Doe, Jane Smith',
    //   link: 'https://example.com',
    //   description:
    //     'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    // },
    // {
    //   title: 'Publication Title',
    //   conferenceName: 'Conference Name',
    //   journalName: '',
    //   authors: 'John Doe, Jane Smith',
    //   link: 'https://example.com',
    //   description:
    //     'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
    // },
  ],
  // Display articles from your medium or dev account. (Optional)
  blog: {
    source: 'dev', // medium | dev
    username: 'therustymate', // to hide blog section, keep it empty
    limit: 10, // How many articles to display. Max is 10.
  },
  googleAnalytics: {
    id: '', // GA3 tracking id/GA4 tag id UA-XXXXXXXXX-X | G-XXXXXXXXXX
  },
  // Track visitor interaction and behavior. https://www.hotjar.com
  hotjar: {
    id: '',
    snippetVersion: 6,
  },
  themeConfig: {
    defaultTheme: 'black',

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
      'procyon',
    ],

    // Custom theme, applied to `procyon` theme
    customTheme: {
      primary: '#fc055b',
      secondary: '#219aaf',
      accent: '#e8d03a',
      neutral: '#2A2730',
      'base-100': '#E3E3ED',
      '--rounded-box': '3rem',
      '--rounded-btn': '3rem',
    },
  },

  // Optional Footer. Supports plain text or HTML.
  footer: `The Rusty (@therustymate)`,

  enablePWA: true,
};

export default CONFIG;
