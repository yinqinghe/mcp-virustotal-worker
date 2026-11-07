// utils/logging.ts

import fs from "fs";
import path from "path";

export function logToFile(message: string) {
  const timestamp = new Date().toISOString();
  const formattedMessage = `[${timestamp}] ${message}`;
  console.error(formattedMessage);
}
