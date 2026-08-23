import type { AnnouncementConfig } from "../types/announcementConfig";

export const announcementConfig: AnnouncementConfig = {
	// 公告标题，留空则走i18n默认标题
	title: "",

	// 公告内容
	content: "PE2Pack x64 Windows PE packer PoC has been published!",

	// 是否允许用户关闭公告
	closable: false,

	link: {
		// 启用链接
		enable: true,
		// 链接文本
		text: "therustymate/PE2Pack",
		// 链接 URL
		url: "https://github.com/therustymate/PE2Pack",
		// 内部链接
		external: true,
	},
};
