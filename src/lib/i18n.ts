import { useMemo } from "react";
import { useSettings } from "../store/settings";

export type Language = "en" | "zh";

const en = {
  app: {
    tagline: "Password recovery assistant",
    settings: "Settings",
    steps: {
      file: "File",
      knowledge: "What you know",
      configure: "Configure",
      recover: "Recover",
      result: "Result",
    },
  },
  home: {
    title: "Recover a forgotten password",
    subtitle:
      "Select an encrypted file. HashRecover detects its format, extracts the password hash, and runs a recovery engine for you — no technical setup required.",
    selectFile: "Select file",
    dragHint: "or drag & drop a file anywhere",
    history: "Recovery history",
    supported: "Supported in this edition",
    privacy:
      "Your files never leave this device. Hashes are processed locally and no data is uploaded.",
  },
  analysis: {
    analyzing: "Analyzing {file}",
    detecting: "Detecting format and extracting the password hash…",
    couldNotAnalyze: "Could not analyze this file",
    chooseAnother: "Choose another file",
    extraction: {
      engineUnavailable:
        "Password recovery for this format is not available.",
      noHash:
        "This file was read successfully, but no password hash was found inside.",
      notEncrypted: "This file does not appear to be password-protected.",
      extractionFailed:
        "Could not extract a password hash from this file. The file may be corrupted or not actually encrypted.",
    },
  },
  fileSummary: {
    encryption: "Encryption: {value}",
    difficultyLabel: "Estimated difficulty: ",
    difficulty: {
      easy: "Easy",
      medium: "Medium",
      hard: "Hard",
    },
  },
  knowledge: {
    title: "What do you remember about the password?",
    subtitle:
      "Pick the option closest to your situation — we'll optimize the attempt automatically.",
    next: "Next",
    chooseAnother: "Choose another file",
    option: {
      partial: {
        title: "I remember part of it",
        description: "A few characters, or the pattern the password follows.",
      },
      common: {
        title: "It's simple and common",
        description: "The kind of password most people use.",
      },
      none: {
        title: "I have no clue",
        description: "Try every combination — slowest but most thorough.",
      },
    },
    sub: {
      "11": {
        title: "I know roughly the length and characters",
        description: "Pick which characters are allowed and how long it is.",
      },
      "12": {
        title: "It's based on passwords I've used before",
        description: "Try variations of your historical passwords.",
      },
      "13": {
        title: "It is made of two known parts",
        description: "Combine two sets of remembered words, numbers, or symbols.",
      },
    },
  },
  configure: {
    title: "Configure the attempt",
    back: "Back",
    start: "Start recovery",
    tab: {
      length: "Length",
      edges: "Start & end",
      lower: "Lowercase",
      upper: "Uppercase",
      digit: "Digits",
      special: "Symbols",
      overview: "Overview",
    },
    group: {
      lower: "Lowercase",
      upper: "Uppercase",
      digit: "Digits",
      special: "Symbols",
    },
    groupTab: {
      lower: "Lowercase letters",
      upper: "Uppercase letters",
      digit: "Digits",
      special: "Symbols",
    },
    length: {
      exact: "Exact length",
      between: "Between two lengths",
      unknown: "No idea (1–16 characters)",
      label: "Length",
      from: "From",
      to: "to",
    },
    edges: {
      startsWith: "The password starts with",
      startsWithPlaceholder: "e.g. summer2024 — leave empty if unknown",
      endsWith: "The password ends with",
      endsWithPlaceholder: "e.g. ! — leave empty if unknown",
      note: "These parts are treated as fixed. The rest is filled with the characters you allow on the other tabs.",
    },
    overview: {
      length: "Length",
      startsWith: "Starts with",
      endsWith: "Ends with",
      characterSet: "Character set",
      characters: "{count} characters",
      range: "{min}–{max} characters",
      all: "all ({count})",
      excluded: "excluded",
      of: "{selected} of {count}",
      allPrintable: "all printable",
      note: "We'll try every combination of the selected characters, starting with the fixed parts above. Fewer characters and a narrower length range make the attempt much faster.",
    },
    history: {
      label: "Historical passwords, one per line",
      note: "We'll try these and common variations of them (case changes, numbers, symbols, years).",
    },
    rules: {
      level: "How many variations to try",
      simple: "Simple",
      simpleDesc: "Fast — a few dozen common variations per password.",
      deep: "Deep",
      deepDesc: "Balanced — hundreds of variations.",
      extreme: "Extreme",
      extremeDesc: "Thorough — tens of thousands of variations, much slower.",
      dictionaryToggle: "Apply password-habit variations",
      dictionaryToggleDesc:
        "Also try common transformations of each word (best66 rules). Slower, but catches many real-world habits.",
    },
    partA: {
      label: "Part 1 — words or numbers you remember, one per line",
    },
    partB: {
      label: "Part 2 — one per line",
    },
    parts: {
      note: "We'll combine every Part 1 entry with every Part 2 entry (Part 1 first).",
    },
    common: {
      builtin: "Use the built-in common passwords",
      builtinDesc: "A curated list of the most popular passwords, with common variations.",
      custom: "Use my own word list",
      customDesc: "A .txt file with one candidate per line.",
      noFile: "No file chosen",
      browse: "Browse…",
      chooseWordList: "Choose a word list",
      wordLists: "Word lists",
    },
    noIdea: {
      note: "We'll try every possible combination up to 16 characters long. This is the most thorough option, but it can take a very long time and may never finish.",
      strategy: "Recovery strategy",
      random: "System built-in random",
      randomDesc: "All printable characters — uses the engine's default random strategy.",
      digits: "Digits only",
      digitsDesc: "1–16 digit numbers (0–9).",
      letters: "Letters only",
      lettersDesc: "1–16 letters (a–z, A–Z).",
      length: "Length:",
      characters: "Characters:",
      oneTo16: "1–16 characters",
      allPrintable: "all printable",
    },
  },
  run: {
    paused: "Paused",
    recovering: "Recovering password…",
    resumeHint: "Resume to continue",
    waiting: "Waiting for the engine to report progress…",
    complete: "{percent}% complete",
    ofCandidates: "{tried} of {total} candidates",
    timeElapsed: "Time elapsed",
    passwordsTried: "Passwords tried",
    speed: "Speed",
    currentCandidate: "Current candidate",
    estimatedTime: "Estimated time",
    detected: "Detected: {device}",
    gpuEnabled: "GPU acceleration enabled",
    cpuAccel: "CPU acceleration",
    detectingHardware: "Detecting hardware…",
    pause: "Pause",
    resume: "Resume",
    cancel: "Cancel",
  },
  result: {
    recovered: "Password recovered",
    yourPassword: "Your password is:",
    fromHistory: "Recovered from your local history:",
    notFound: "Password not found",
    notFoundBody: "The recovery attempt did not find the password.",
    cancelled: "Recovery interrupted",
    cancelledBody: "The recovery attempt was interrupted before completion.",
    copy: "Copy password",
    copied: "Copied",
    tryAgain: "Try again",
    differentMethod: "Try a different method",
    another: "Recover another password",
    anotherFile: "Choose another file",
    error: {
      hashUnreadable: "This password hash could not be read.",
      tempWorkspaceFailed: "Could not create temporary files.",
      hashPrepareFailed: "Could not prepare the password hash.",
      methodUnavailable: "This recovery method is not available in your current version.",
      engineUnavailable: "No recovery engine is available.",
      missingWordlist: "The required password dictionary is not available.",
      missingRules: "The required password rules are not available.",
    },
  },
  history: {
    title: "Recovery history",
    subtitle:
      "Passwords recovered on this device. Repeat attempts are answered instantly from here.",
    clear: "Clear local records",
    confirmClear: "Confirm clear",
    confirmClearNote: "This removes every locally stored recovery. This cannot be undone.",
    back: "Back",
    loading: "Loading…",
    emptyTitle: "No recovered passwords yet",
    emptyBody: "Successfully recovered passwords appear here for reuse.",
    engineGPU: "GPU",
    engineCPU: "CPU",
    engineHistory: "Recovery history",
    strategy: {
      dictionary: "Common passwords",
      partial: "Known part",
      pattern: "Password habits",
      bruteforce: "Brute force",
      combinator: "Combined parts",
    },
  },
  settings: {
    title: "Settings",
    close: "Close settings",
    appearance: "Appearance",
    dark: "Dark",
    light: "Light",
    fontSize: "Font size",
    fontSizes: {
      small: "Small",
      normal: "Normal",
      large: "Large",
      larger: "Larger",
    },
    language: "Language",
    gpuAcceleration: "GPU acceleration",
    gpuAccelerationHint:
      "When enabled, use GPU acceleration with fallback to CPU. When disabled, use CPU only.",
  },
  charGroup: {
    selectAll: "Select all",
    excludedNote:
      "This group is excluded. Ticking Select all (or any character) will include it again.",
    space: "space",
  },
};

const zh: typeof en = {
  app: {
    tagline: "密码恢复助手",
    settings: "设置",
    steps: {
      file: "文件",
      knowledge: "您知道什么",
      configure: "配置",
      recover: "恢复",
      result: "结果",
    },
  },
  home: {
    title: "恢复忘记的密码",
    subtitle:
      "选择加密文件。HashRecover 会自动检测格式、提取密码哈希并运行恢复引擎——无需任何技术设置。",
    selectFile: "选择文件",
    dragHint: "或将文件拖放到任意位置",
    history: "恢复历史记录",
    supported: "本版本支持的文件类型",
    privacy: "您的文件永远不会离开此设备。哈希仅在本地处理，不会上传任何数据。",
  },
  analysis: {
    analyzing: "正在分析 {file}",
    detecting: "正在检测格式并提取密码哈希…",
    couldNotAnalyze: "无法分析此文件",
    chooseAnother: "选择另一个文件",
    extraction: {
      engineUnavailable: "当前版本不支持此格式的密码恢复。",
      noHash: "文件读取成功，但未在其中找到密码哈希。",
      notEncrypted: "此文件似乎没有设置密码保护。",
      extractionFailed:
        "无法从此文件提取密码哈希。文件可能已损坏或实际上并未加密。",
    },
  },
  fileSummary: {
    encryption: "加密方式：{value}",
    difficultyLabel: "预计难度：",
    difficulty: {
      easy: "简单",
      medium: "中等",
      hard: "困难",
    },
  },
  knowledge: {
    title: "您还记得密码的哪些信息？",
    subtitle: "选择最接近您情况的一项——我们会自动优化尝试方式。",
    next: "下一步",
    chooseAnother: "选择另一个文件",
    option: {
      partial: {
        title: "记得一部分",
        description: "记得几个字符，或密码遵循的规律。",
      },
      common: {
        title: "简单且常见",
        description: "大多数人会使用的那种密码。",
      },
      none: {
        title: "完全没有头绪",
        description: "尝试所有组合——最慢但最全面。",
      },
    },
    sub: {
      "11": {
        title: "大致知道长度和包含的字符",
        description: "选择允许的字符范围以及密码长度。",
      },
      "12": {
        title: "基于我以前用过的密码",
        description: "尝试历史密码的各种常见变体。",
      },
      "13": {
        title: "由两个已知部分组成",
        description: "组合两套记得的单词、数字或符号。",
      },
    },
  },
  configure: {
    title: "配置恢复方式",
    back: "返回",
    start: "开始恢复",
    tab: {
      length: "长度",
      edges: "开头与结尾",
      lower: "小写",
      upper: "大写",
      digit: "数字",
      special: "符号",
      overview: "概览",
    },
    group: {
      lower: "小写",
      upper: "大写",
      digit: "数字",
      special: "符号",
    },
    groupTab: {
      lower: "小写字母",
      upper: "大写字母",
      digit: "数字",
      special: "符号",
    },
    length: {
      exact: "固定长度",
      between: "长度范围",
      unknown: "不知道（1–16 位）",
      label: "长度",
      from: "从",
      to: "到",
    },
    edges: {
      startsWith: "密码开头是",
      startsWithPlaceholder: "例如 summer2024——不知道可留空",
      endsWith: "密码结尾是",
      endsWithPlaceholder: "例如 !——不知道可留空",
      note: "这些部分是固定的。其余部分由您在其他标签页允许的字符填充。",
    },
    overview: {
      length: "长度",
      startsWith: "开头",
      endsWith: "结尾",
      characterSet: "字符集",
      characters: "{count} 个字符",
      range: "{min}–{max} 个字符",
      all: "全部（{count}）",
      excluded: "已排除",
      of: "{selected} / {count}",
      allPrintable: "所有可打印字符",
      note: "我们将尝试所选字符的所有组合，从上面的固定部分开始。字符越少、长度范围越窄，尝试速度越快。",
    },
    history: {
      label: "历史密码，每行一个",
      note: "我们将尝试这些密码及其常见变体（大小写变化、数字、符号、年份）。",
    },
    rules: {
      level: "尝试多少种变体",
      simple: "简单",
      simpleDesc: "快速——每个密码只做几十种常见变形。",
      deep: "深度",
      deepDesc: "均衡——数百种变形。",
      extreme: "极限",
      extremeDesc: "彻底——数万种变形，速度慢很多。",
      dictionaryToggle: "应用密码习惯变形",
      dictionaryToggleDesc:
        "同时尝试每个单词的常见变形（best66 规则）。更慢，但能覆盖很多真实习惯。",
    },
    partA: {
      label: "第 1 部分——您记得的单词或数字，每行一个",
    },
    partB: {
      label: "第 2 部分——每行一个",
    },
    parts: {
      note: "我们将把每个第 1 部分条目与每个第 2 部分条目组合（第 1 部分在前）。",
    },
    common: {
      builtin: "使用内置的常见密码列表",
      builtinDesc: "精选的最常用密码列表，包含常见变体。",
      custom: "使用我自己的字典",
      customDesc: "一个 .txt 文件，每行一个候选词。",
      noFile: "未选择文件",
      browse: "浏览…",
      chooseWordList: "选择字典",
      wordLists: "字典",
    },
    noIdea: {
      note: "我们将尝试最长为 16 个字符的所有可能组合。这是最全面的选项，但可能需要很长时间，甚至可能无法完成。",
      strategy: "恢复策略",
      random: "系统内置随机",
      randomDesc: "所有可打印字符——使用引擎默认的随机策略。",
      digits: "纯数字",
      digitsDesc: "1–16 位数字（0–9）。",
      letters: "纯字母",
      lettersDesc: "1–16 位字母（a–z, A–Z）。",
      length: "长度：",
      characters: "字符：",
      oneTo16: "1–16 个字符",
      allPrintable: "所有可打印字符",
    },
  },
  run: {
    paused: "已暂停",
    recovering: "正在恢复密码…",
    resumeHint: "继续以恢复运行",
    waiting: "正在等待引擎报告进度…",
    complete: "{percent}% 已完成",
    ofCandidates: "{tried} / {total} 个候选",
    timeElapsed: "已用时",
    passwordsTried: "已尝试密码数",
    speed: "速度",
    currentCandidate: "当前候选",
    estimatedTime: "预计剩余时间",
    detected: "检测到：{device}",
    gpuEnabled: "GPU 加速已启用",
    cpuAccel: "CPU 加速",
    detectingHardware: "正在检测硬件…",
    pause: "暂停",
    resume: "继续",
    cancel: "取消",
  },
  result: {
    recovered: "密码已恢复",
    yourPassword: "您的密码是：",
    fromHistory: "来自本地恢复历史：",
    notFound: "未找到密码",
    notFoundBody: "本次恢复尝试未找到密码。",
    cancelled: "恢复已中断",
    cancelledBody: "本次恢复尝试在完成前被中断。",
    copy: "复制密码",
    copied: "已复制",
    tryAgain: "重试",
    differentMethod: "换一种方式尝试",
    another: "恢复另一个密码",
    anotherFile: "选择另一个文件",
    error: {
      hashUnreadable: "无法识别此文件的密码格式。",
      tempWorkspaceFailed: "无法创建临时文件。",
      hashPrepareFailed: "无法准备密码哈希。",
      methodUnavailable: "当前版本不支持此恢复方式。",
      engineUnavailable: "恢复引擎不可用。",
      missingWordlist: "所需的密码词典不可用。",
      missingRules: "所需的密码规则不可用。",
    },
  },
  history: {
    title: "恢复历史记录",
    subtitle: "此设备上已恢复的密码。重复尝试会从这里立即得到答案。",
    clear: "清空本地记录",
    confirmClear: "确认清空",
    confirmClearNote: "这将删除本机存储的所有恢复记录。此操作无法撤销。",
    back: "返回",
    loading: "加载中…",
    emptyTitle: "暂无已恢复的密码",
    emptyBody: "成功恢复的密码会显示在这里，以便复用。",
    engineGPU: "GPU",
    engineCPU: "CPU",
    engineHistory: "恢复历史记录",
    strategy: {
      dictionary: "常见密码",
      partial: "已知部分",
      pattern: "密码习惯",
      bruteforce: "暴力破解",
      combinator: "组合部分",
    },
  },
  settings: {
    title: "设置",
    close: "关闭设置",
    appearance: "外观",
    dark: "深色",
    light: "浅色",
    fontSize: "字体大小",
    fontSizes: {
      small: "小",
      normal: "标准",
      large: "大",
      larger: "更大",
    },
    language: "语言",
    gpuAcceleration: "GPU 加速",
    gpuAccelerationHint:
      "开启时优先使用 GPU 加速，失败后回退到 CPU。关闭时只使用 CPU。",
  },
  charGroup: {
    selectAll: "全选",
    excludedNote: "该字符组已被排除。勾选“全选”或任意字符即可重新包含。",
    space: "空格",
  },
};

const messages = { en, zh };

type DeepKeys<T, P extends string = ""> = {
  [K in keyof T]: T[K] extends string
    ? `${P}${string & K}`
    : DeepKeys<T[K], `${P}${string & K}.`>;
}[keyof T];

export type MessageKey = DeepKeys<typeof messages.en>;

type Params = Record<string, string | number | undefined>;

export function translate(lang: Language, key: MessageKey, params?: Params): string {
  let value: unknown = messages[lang];
  for (const part of key.split(".")) {
    value = (value as Record<string, unknown>)[part];
  }
  const text = typeof value === "string" ? value : key;
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (_, name: string) => {
    const replacement = params[name];
    return replacement === undefined ? `{${name}}` : String(replacement);
  });
}

/** Translation helper bound to the current UI language. */
export function useT() {
  const language = useSettings((s) => s.language);
  return useMemo(() => (key: MessageKey, params?: Params) => translate(language, key, params), [language]);
}
