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
          projects: ['therustymate/therustymate', 'therustymate/unofficial-projects'], // These projects will not be displayed. example: ['arifszn/my-project1', 'arifszn/my-project2']
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
          title: 'Elite Console',
          description:
            'Elite Console project is an enhanced and high-performance MITM (Man-In-The-Middle) attack tool, designed for advanced capabilities for network penetration testing.',
          imageUrl:
            './unofficial-projects/Elite Console/logo.png',
          link: 'https://github.com/therustymate/Elite-Console',
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
    dev: '',
    stackoverflow: '', // example: '1/jeff-atwood'
    skype: '',
    telegram: '',
    website: 'https://therustymate.github.io/blog',
    phone: '',
    tryhackme: 'therustymate',
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
  fields: [
    'Penetration Testing',
    'Web Hacking',
    'Network Hacking',
    'Binary Exploitation'
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
    // {
    //   name: 'Lorem ipsum',
    //   body: 'Lorem ipsum dolor sit amet',
    //   year: 'March 2022',
    //   link: 'https://example.com',
    // },
  ],
  achievements: [
    // 2024 Awards
    {
      name: 'Facilitating & Enhancing the Learning Environment of the Class in Year 11 Digital Technology',
      body: "Western Springs College",
      year: 'October, 2024',
      link: 'https://wscyearbook.co.nz/2024/wsc-category/year-11-prize-giving/',
    },
    {
      name: 'Outstanding Application in Year 11 English Language Intermediate',
      body: "Western Springs College",
      year: 'October, 2024',
      link: 'https://wscyearbook.co.nz/2024/wsc-category/year-11-prize-giving/',
    },
    {
      name: 'Outstanding Application in Year 11 Mathematics',
      body: "Western Springs College",
      year: 'October, 2024',
      link: 'https://wscyearbook.co.nz/2024/wsc-category/year-11-prize-giving/',
    },
    {
      name: 'Facilitating & Enhancing the Learning Environment of the Class in Year 11 Business Studies',
      body: "Western Springs College",
      year: 'October, 2024',
      link: 'https://wscyearbook.co.nz/2024/wsc-category/year-11-prize-giving/',
    },
    {
      name: 'International Student Award for a full & positive contribution to all aspects of the learning environment',
      body: "Western Springs College",
      year: 'October, 2024',
      link: '',
    },
    {
      name: 'The Whenua Graham Woolford Caring Award',
      body: "Western Springs College",
      year: 'October, 2024',
      link: '',
    },
    {
      name: 'Excellent Academic Achievement',
      body: "Western Springs College International Department",
      year: 'August 6, 2024',
      link: '',
    },

    // 2023 Awards
    {
      name: 'Significant Progress in Year 10 Science',
      body: "Western Springs College",
      year: 'December, 2023',
      link: '',
    },
    {
      name: 'Significant Progress in Year 10 Social Studies',
      body: "Western Springs College",
      year: 'December, 2023',
      link: '',
    },
    {
      name: 'Outstanding Achievement in Year 10 Digital Technology',
      body: "Western Springs College",
      year: 'December, 2023',
      link: '',
    },
    {
      name: 'Year 10 International Student Award for Outstanding Progress and Positive Attitude',
      body: "Western Springs College",
      year: 'December, 2023',
      link: '',
    }
  ],
  educations: [
    {
      institution: 'TryHackMe - Cyber Security 101',
      degree: 'Course',
      from: '2025-06/20',
      to: '2025-08/15',
    },
    // {
    //   institution: 'TryHackMe',
    //   degree: 'Junior Penetration Tester',
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
    source: '', // medium | dev
    username: '', // to hide blog section, keep it empty
    limit: 10, // How many articles to display. Max is 10.
  },
  googleAnalytics: {
    id: 'G-YSLDYLXHP2', // GA3 tracking id/GA4 tag id UA-XXXXXXXXX-X | G-XXXXXXXXXX
  },
  // Track visitor interaction and behavior. https://www.hotjar.com
  hotjar: {
    id: '',
    snippetVersion: 6,
  },
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
