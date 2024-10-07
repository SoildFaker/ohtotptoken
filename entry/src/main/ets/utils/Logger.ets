import { hilog } from '@kit.PerformanceAnalysisKit';

/**
 * Common log for all features.
 */
export class Logger {
  private domain: number;
  private prefix: string;
  private format: string = '%{public}s, %{public}s';

  constructor(prefix: string) {
    this.prefix = prefix;
    this.domain = 0xFF00;
  }

  debug(...args: string[]): void {
    hilog.debug(this.domain, this.prefix, this.format, args);
  }

  info(...args: string[]): void {
    hilog.info(this.domain, this.prefix, this.format, args);
  }

  warn(...args: string[]): void {
    hilog.warn(this.domain, this.prefix, this.format, args);
  }

  error(...args: string[]): void {
    hilog.error(this.domain, this.prefix, this.format, args);
  }

  fatal(...args: string[]): void {
    hilog.fatal(this.domain, this.prefix, this.format, args);
  }

  isLoggable(level: number): void {
    hilog.isLoggable(this.domain, this.prefix, level);
  }
}

export default new Logger('[TOTP-TOKEN]');