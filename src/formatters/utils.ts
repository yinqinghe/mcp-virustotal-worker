// src/formatters/utils.ts

import { logToFile } from '../utils/logging.js';

export function formatDateTime(timestamp: number | string | null): string {
  try {
    if (!timestamp) return 'N/A';
    const date = typeof timestamp === 'number' 
      ? new Date(timestamp * 1000)
      : new Date(timestamp);
    return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  } catch (error) {
    logToFile(`Error formatting datetime: ${error}`);
    return 'Invalid Date';
  }
}

export function formatPercentage(num: number, total: number): string {
  try {
    if (total === 0) return '0.0%';
    return `${((num / total) * 100).toFixed(1)}%`;
  } catch (error) {
    logToFile(`Error formatting percentage: ${error}`);
    return '0.0%';
  }
}

export function formatDetectionResults(results: any): string {
  try {
    const malicious = results?.malicious || 0;
    const suspicious = results?.suspicious || 0;
    const harmless = results?.harmless || 0;
    const undetected = results?.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    if (total === 0) {
      return 'Detections: No detection data available';
    }

    if (malicious > 0) {
      return `🔴 Detections: ${malicious}/${total} engines flagged as malicious (⚠️ ${suspicious} suspicious, ✅ ${harmless} clean, ${undetected} undetected)`;
    }
    if (suspicious > 0) {
      return `⚠️ Detections: 0/${total} malicious (⚠️ ${suspicious} suspicious, ✅ ${harmless} clean, ${undetected} undetected)`;
    }
    return `✅ Detections: 0/${total} malicious (Clean)`;
  } catch (error) {
    logToFile(`Error formatting detection results: ${error}`);
    return 'Error formatting detection results';
  }
}
