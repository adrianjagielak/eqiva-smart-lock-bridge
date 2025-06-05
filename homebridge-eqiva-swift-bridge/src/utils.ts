export function sortStatusJsonForLogging<T extends Record<string, unknown>>(obj: T): Record<string, unknown> {
  const sorted: Record<string, unknown> = {};

  // Add timestamp first if present
  if ('timestamp' in obj) {
    sorted.timestamp = obj.timestamp;
  }

  // Add all other keys sorted, excluding timestamp
  Object.keys(obj)
    .filter((key) => key !== 'timestamp')
    .sort()
    .forEach((key) => {
      sorted[key] = obj[key];
    });

  return sorted;
}