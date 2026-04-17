
export type LicenseInfo = {
  type: string;
  title: string;
  points: string[];
};

const LICENSE_GUIDANCE: Record<string, LicenseInfo> = {
  MIT: {
    type: "MIT License",
    title: "Very open license",
    points: [
      "You can use this code in any project.",
      "You can change the code and share your version.",
      "You can use it in paid/commercial products.",
      "You must keep the original license and copyright note.",
      "The author is not responsible if something breaks.",
    ],
  },
  "Apache-2.0": {
    type: "Apache License 2.0",
    title: "Open license with extra patent safety",
    points: [
      "You can use this code in personal or business projects.",
      "You can change it, share it, and sell products using it.",
      "You must keep license, copyright, and NOTICE files.",
      "Contributors also give patent rights for this code.",
      "If you change major parts, clearly mention your changes.",
    ],
  },
  "GPL-3.0": {
    type: "GNU GPL v3.0",
    title: "Open-source only when shared",
    points: [
      "You can use and edit this code, even for business.",
      "You can sell software made from it.",
      "If you share the app, you must share the source code too.",
      "Your shared version must stay under GPL-3.0.",
      "You must keep license and copyright notices.",
    ],
  },
  "BSD-3-Clause": {
    type: "BSD 3-Clause",
    title: "Open license with simple rules",
    points: [
      "You can use this code in open-source or private apps.",
      "You can edit it, share it, and sell products using it.",
      "You must keep the license and copyright text.",
      "Do not use the author names to promote your product without permission.",
      "The authors are not liable for problems caused by the code.",
    ],
  },
  "MPL-2.0": {
    type: "Mozilla Public License 2.0",
    title: "Mix of open and closed allowed",
    points: [
      "You can use this in business and personal projects.",
      "You can sell software that includes this code.",
      "If you edit MPL files and share them, share those file sources too.",
      "Other separate files can stay closed-source.",
      "Keep license headers and notices in MPL files.",
    ],
  },
};

export function getLicenseInfo(license: string | null): LicenseInfo | null {
  if (!license) return null;

  if (LICENSE_GUIDANCE[license]) {
    return LICENSE_GUIDANCE[license];
  }

  return {
    type: license,
    title: "License detected",
    points: [
      "Read the full license before using this repo.",
      "Check if business/commercial use is allowed.",
      "Check if selling products with this code is allowed.",
      "Keep any required license and credit notices.",
      "If unsure, ask a legal expert before release.",
    ],
  };
}