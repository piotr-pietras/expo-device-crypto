import { Buffer } from "buffer";

export const base64ToPem = (base64: string, label = "DATA") => {
  const normalized = base64.replace(/\s+/g, "");
  const wrapped = normalized.match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
};

export const base64ToHex = (base64: string) => {
  return Buffer.from(base64, "base64").toString("hex");
};
