import type { PartialMessages } from "./types.js";

// 部分翻译：缺失的内容以英文显示。
export const zh: PartialMessages = {
  severity: { critical: "严重", high: "高", medium: "中", low: "低" },
  report: {
    heading: "dotation：你的代码卫生",
    target: (path, files) => `已扫描：${path}（${files} 个文件）`,
    clean: "没有发现问题。你的代码看起来很干净，干得好。",
    score: (s) => `卫生评分：${s}/100`,
    counts: (parts) => `发现：${parts}`,
    more: (n) => `……还有 ${n} 个。加上 --all 重新运行即可查看全部。`,
    why: "原因",
    fix: "如何修复",
    engines: "引擎",
  },
};
