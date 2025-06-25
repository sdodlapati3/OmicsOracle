/**
 * Utility function to conditionally join class names
 * Similar to the popular `clsx` library but simplified
 */
export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}
