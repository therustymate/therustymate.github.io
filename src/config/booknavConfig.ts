import type { BooknavGroup, BooknavPageConfig } from "../types/booknavConfig";

// 书签导航页面配置
export const booknavPageConfig: BooknavPageConfig = {
	// 页面标题，如果留空则使用 i18n 中的翻译
	title: "",

	// 页面描述文本，如果留空则使用 i18n 中的翻译
	description: "",

	// favicon 自动获取配置
	favicon: {
		// 书签未填写 icon 时，是否自动获取目标站点的 favicon 图标
		enabled: true,

		// favicon 接口地址，{domain} 为占位符，会被替换成目标站点域名
		// 更换接口只需保证地址里含有 {domain}，例如：
		//   https://a.favicon.im/{domain}
		//   https://favicon.im/{domain}
		api: "https://a.favicon.im/{domain}",
	},
};

// 书签导航配置
// 每个数组项是一个分类组，分类组内的 items 是该分类下的书签
export const booknavConfig: BooknavGroup[] = [
	{
		id: "dev",
		name: "Dashboard",
		icon: "material-symbols:code-rounded",
		desc: "",
		weight: 100,
		items: [
			{
				title: "GitHub",
				url: "https://github.com",
				desc: "",
				// icon 字段可以使用 astro-icon 图标库的图标名称
				// 也可以使用图片 URL 和本地图片路径
				// 不填则会通过接口自动获取目标站点的 favicon 图标（需要在上面配置）
				icon: "fa7-brands:github",
				weight: 10,
			},
			{
				title: "Cloudflare",
				url: "https://cloudflare.com",
				desc: "",
				weight: 6,
			},
			{
				title: "TryHackMe",
				url: "https://tryhackme.com",
				desc: "",
				weight: 6,
			},
      {
				title: "Binary Ninja",
				url: "https://binary.ninja",
				desc: "",
				weight: 6,
			},
      {
				title: "UnknownCheats",
				url: "https://www.unknowncheats.me/forum/index.php",
				desc: "",
				weight: 6,
			},
      {
				title: "WhatsApp",
				url: "https://whatsapp.com/",
				desc: "",
				weight: 6,
			},
		],
	},
	{
		id: "tools",
		name: "Tools",
		icon: "material-symbols:build-outline-rounded",
		desc: "",
		weight: 80,
		items: [
			{
				title: "NtDoc",
				url: "https://ntdoc.m417z.com/",
				desc: "",
				weight: 10,
			},
      {
				title: "CyberChef",
				url: "https://toolbox.itsec.tamu.edu/",
				desc: "",
				weight: 10,
			},
      {
				title: "Compiler Explorer",
				url: "https://godbolt.org/",
				desc: "",
				weight: 10,
			},
      {
				title: "Vx Underground",
				url: "https://vx-underground.org/",
				desc: "",
				weight: 10,
			},
      {
				title: "ArgFuscator",
				url: "https://argfuscator.net/",
				desc: "",
				weight: 10,
			},
		],
	},
	{
		id: "resources",
		name: "Resources",
		icon: "material-symbols:auto-stories-outline-rounded",
		desc: "",
		weight: 70,
		items: [
			{
				title: "Red Team Notes 2.0",
				url: "https://dmcxblue.gitbook.io/red-team-notes-2-0",
				desc: "",
				icon: "",
				weight: 10,
			},
      {
				title: "Red Team Notes",
				url: "https://www.ired.team/",
				desc: "",
				icon: "",
				weight: 10,
			},
      {
				title: "레드팀 플레이북",
				url: "https://www.xn--hy1b43d247a.com/",
				desc: "",
				icon: "",
				weight: 10,
			},
		],
	},
];
