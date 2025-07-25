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
    tryhackme: 'therustymate',
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

    'Ghidra',
    'Binary Ninja',
    'dnSpy',
    'radare2',
    'GDB',

    'Nmap',
    'Masscan',
    'Metasploit',
    'Netcat',

    'Burp Suite',
    'Gobuster',

    'Wireshark',
    'mitmproxy',
    'bettercap',
    'BeEF',
    'Social Engineering Toolkit (SET)',
    'airmon-ng',
    'airodump-ng',
    'wifite',

    'Maltego',

    'Bulk Extractor',

    'Assembly (x86)',
    'C',
    'C++',
    'C#',
    'Python',
    'SQL'
  ],
  fields: [
    'Malware Analysis',
    'Reverse Engineering',
    'Binary Exploitation',
    'Red Teaming',
    'Network Hacking',
    'Penetration Testing',
    'Web Hacking',
    'Cryptography'
  ],
  experiences: [
    {
      company: 'Public High School',
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
    // {
    //   name: 'Lorem ipsum',
    //   body: 'Lorem ipsum dolor sit amet',
    //   year: 'March 2022',
    //   link: 'https://example.com',
    // },
  ],
  achievements: [
    {
      name: 'World Wide Web',
      body: "Completing the 'How The Web Works' module",
      year: 'June 21, 2025',
      link: 'https://assets.tryhackme.com/room-badges/42b17b72ce81545716b4653b3eca8ff4.png',
    },
    {
      name: 'Security Awareness',
      body: 'Completing the cyber security awareness module',
      year: 'June 20, 2025',
      link: 'https://assets.tryhackme.com/room-badges/9430579ece615116367abbe15c565e95.png',
    },
    {
      name: 'First Four',
      body: 'Completing four rooms in your first week of joining!',
      year: 'June 20, 2025',
      link: 'https://assets.tryhackme.com/room-badges/2e11b7a6d704440d4df2322269fd3906.png',
    },
    {
      name: 'cat linux.txt',
      body: 'Being competent in Linux',
      year: 'June 20, 2025',
      link: 'https://assets.tryhackme.com/room-badges/b0f6028840e19e49071bee84e096150c.png',
    },
    {
      name: 'Webbed',
      body: 'Understands how the world wide web works',
      year: 'June 20, 2025',
      link: 'https://assets.tryhackme.com/room-badges/daabd1916f121bab3f8ae50e620c4cf5.png',
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
