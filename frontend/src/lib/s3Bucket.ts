export function validS3Bucket(bucket: string): boolean {
  return /^(?=.{3,63}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(bucket)
    && !bucket.includes('..') && !/^\d+\.\d+\.\d+\.\d+$/.test(bucket);
}
