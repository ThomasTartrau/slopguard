// Synthetic fixture: a small TypeScript file used by the file-level metric rules.
import { add } from "./math";
import { format } from "./format";
import { Logger } from "./logger";

export function double(value: number): number {
  return add(value, value);
}

export function label(value: number): string {
  return format(value);
}

// The third function keeps the file plausible without growing it.
export function log(logger: Logger, value: number): void {
  logger.info(label(double(value)));
}
